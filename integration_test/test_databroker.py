#!/usr/bin/env python3
# /********************************************************************************
# * Copyright (c) 2022 Contributors to the Eclipse Foundation
# *
# * See the NOTICE file(s) distributed with this work for additional
# * information regarding copyright ownership.
# *
# * This program and the accompanying materials are made available under the
# * terms of the Apache License 2.0 which is available at
# * http://www.apache.org/licenses/LICENSE-2.0
# *
# * SPDX-License-Identifier: Apache-2.0
# ********************************************************************************/

import json
import logging
import os

import asyncio
import pytest
import pytest_asyncio

from gen_proto.sdv.databroker.v1.types_pb2 import Datapoint
from helper import Databroker

logger = logging.getLogger(__name__)
logger.setLevel(os.getenv("LOG_LEVEL", "WARN"))

DATABROKER_ADDRESS = os.environ.get("DATABROKER_ADDRESS", "127.0.0.1:55555")


@pytest_asyncio.fixture
async def setup_helper() -> Databroker:
    logger.info("Using DATABROKER_ADDRESS={}".format(DATABROKER_ADDRESS))
    helper = await Databroker.ConnectedDatabroker(DATABROKER_ADDRESS)
    return helper


@pytest.mark.asyncio
async def test_databroker_connection() -> None:
    logger.info("Connecting to VehicleDataBroker {}".format(DATABROKER_ADDRESS))
    helper = await Databroker.ConnectedDatabroker(DATABROKER_ADDRESS)
    await helper.get_metadata()
    logger.info("Databroker._address =  {}".format(helper._address))
    await helper.close()


@pytest.mark.asyncio
async def test_feeder_metadata_registered(setup_helper: Databroker) -> None:
    helper = setup_helper
    feeder_names = [
        "Vehicle.Speed",
        "Vehicle.Powertrain.Transmission.CurrentGear",
        "Vehicle.Chassis.ParkingBrake.IsEngaged",
        "Vehicle.Powertrain.ElectricMotor.Torque",
    ]

    meta = await helper.get_metadata(feeder_names)
    logger.debug(
        "# get_metadata({}) -> \n{}".format(
            feeder_names, str(meta).replace("\n", " ")
        )
    )

    assert len(meta) > 0, "databroker metadata is empty"  # nosec B101
    assert len(meta) == len(  # nosec B101
        feeder_names
    ), "Filtered meta with unexpected size: {}".format(meta)
    meta_list = helper.metadata_to_json(meta)
    logger.debug("get_metadata() --> \n{}".format(json.dumps(meta_list, indent=2)))

    meta_names = [d["name"] for d in meta_list]

    for name in feeder_names:
        assert name in meta_names, "{} not registered!".format(name)  # nosec B101

        name_reg = meta_list[meta_names.index(name)]

        assert len(name_reg) == 4 and name_reg["name"] == name  # nosec B101
        logger.info("[feeder] Found metadata: {}".format(name_reg))
        # TODO: check for expected types?
        # assert (  # nosec B101
        #     name_reg["data_type"] == DataType.UINT32
        # ), "{} datatype is {}".format(name, name_reg["data_type"])

    await helper.close()


@pytest.mark.asyncio
async def test_events(setup_helper: Databroker) -> None:
    helper: Databroker = setup_helper

    timeout = 3
    datapoint_speed = "Vehicle.Speed" # float
    datapoint_engine_load = "Vehicle.Powertrain.ElectricMotor.Torque" # int16
    alias_speed = "speed"
    alias_load = "load"

    query = "SELECT {} as {}, {} as {}".format(datapoint_speed, alias_speed, datapoint_engine_load, alias_load)

    events = []
    # inner function for collecting subscription events

    def inner_callback(name: str, dp: Datapoint):
        dd = helper.datapoint_to_dict(name, dp)
        events.append(dd)

    logger.info("# subscribing('{}', timeout={})".format(query, timeout))

    subscription = asyncio.create_task(
        helper.subscribe_datapoints(query, timeout=timeout, sub_callback=inner_callback)
    )

    # Give the subscription task a brief moment to register before publishing updates.
    await asyncio.sleep(0.2)

    # Ensure at least one datapoint changes value during the subscription window.
    set_speed_1 = asyncio.create_task(
        helper.set_float_datapoint(datapoint_speed, 40.0)
    )
    set_load = asyncio.create_task(
        helper.set_int16_datapoint(datapoint_engine_load, 10)
    )

    await set_speed_1
    await set_load
    await asyncio.sleep(0.2)
    await helper.set_float_datapoint(datapoint_speed, 41.0)
    await subscription

    logger.debug("Received events:{}".format(events))

    assert len(events) > 0, "No events from feeder for {} sec.".format(  # nosec B101
        timeout
    )

    # list of received names
    event_names = set([e["name"] for e in events])
    # list of received values
    alias_values1 = set([e["value"] for e in events if e["name"] == alias_speed])
    alias_values2 = set([e["value"] for e in events if e["name"] == alias_load])

    logger.debug("  --> names  : {}".format(event_names))
    # event_values = [e['value'] for e in events]
    # logger.debug("  --> values : {}".format(event_values))
    # logger.debug("  --> <{}> : {}".format(name, event_values_name))

    assert set([alias_speed, alias_load]) == set(  # nosec B101
        event_names
    ), "Unexpected event aliases received: {}".format(event_names)

    # don't be too harsh, big capture.log file may have gaps in some of the events
    assert (  # nosec B101
        len(alias_values1) > 1 or len(alias_values2) > 1
    ), "{} values not changing: {}. Is feeder running?".format(alias_speed, alias_values1)

    await helper.close()


if __name__ == "__main__":
    pytest.main(["-vvs", "--log-cli-level=INFO", os.path.abspath(__file__)])
