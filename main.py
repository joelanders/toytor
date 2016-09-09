#!/usr/bin/env python3.5
import asyncio
import string
import torpylle
import signal
import functools
from aiomanhole import start_manhole
from control import ControlServer
import logging


logging.basicConfig(
    format='%(levelname)s %(asctime)s %(name)-23s %(message)s',
    datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def main():
    loop = asyncio.get_event_loop()
    control_server = ControlServer(9090)
    loop.run_until_complete(control_server.start())

    start_manhole(port=9089)
    logger.info('entering main')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logger.info("got keyboard interrupt")
    finally:
        # TODO: if we do 'quit' in control channel and later ctrl-c,
        # tasks get cancelled twice
        logger.info("stopping control_server")
        loop.run_until_complete(control_server.stop())


if __name__ == '__main__':
    main()
