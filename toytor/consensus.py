import asyncio
import aiohttp
import zlib
import stem
import os.path
import random
from stem.descriptor import DocumentHandler, parse_file, server_descriptor
import logging


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# DIRAUTHS = ["128.31.0.39:9131", "86.59.21.38:80", "194.109.206.212:80",
#             "82.94.251.203:80", "131.188.40.189:80", "193.23.244.244:80",
#             "171.25.193.9:443", "154.35.175.225:80", "199.254.238.52:80"]
DIRAUTHS = ['127.0.0.1:7000', '127.0.0.1:7001',
            '127.0.0.1:7002', '127.0.0.1:7003']
CONS_FILE = 'consensus'
CONS_URL = 'http://%s/tor/status-vote/current/consensus'
DESC_URL = 'http://%s/tor/server/d/'  # TODO: appending ID to end here is jank


async def download_url(url):
    async with aiohttp.ClientSession() as session:
        logger.info('downloading %s' % url)
        resp = await asyncio.wait_for(session.get(url), timeout=5)
        text = await asyncio.wait_for(resp.text(), timeout=5)
        return text


async def try_all_for_url(url_without_host):
    # random.shuffle is in-place, which I don't like
    for host in random.sample(DIRAUTHS, len(DIRAUTHS)):
        try:
            return await download_url(url_without_host % host)
        except asyncio.TimeoutError:
            logger.info('failed to get %s from %s' % (url_without_host, host))
    else:
        raise Exception('couldn\'t talk to any dirauths')


async def server_descriptor(relay_digest):
    desc_string = await try_all_for_url(DESC_URL + relay_digest)
    return stem.descriptor.server_descriptor.ServerDescriptor(desc_string)


async def cached_consensus():
    if not os.path.isfile(CONS_FILE):
        logger.info('not found, downloading')
        with open(CONS_FILE, 'w') as f:
            cons = await try_all_for_url(CONS_URL)
            f.write(cons)
    else:
        logger.info('found, loading from disk')

    return next(parse_file(
        CONS_FILE,
        descriptor_type='network-status-consensus-3 1.0',
        document_handler=DocumentHandler.DOCUMENT,
    ))


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    consensus = loop.run_until_complete(cached_consensus())
    for relay in random.sample(list(consensus.routers.values()), 1):
        logger.info("%s" % relay.fingerprint)
        desc = loop.run_until_complete(server_descriptor(relay.digest))
        logger.info("%s" % desc.ntor_onion_key)
