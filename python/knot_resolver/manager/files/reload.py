import logging

from knot_resolver.controller.registered_workers import command_registered_workers
from knot_resolver.datamodel import KresConfig

logger = logging.getLogger(__name__)


async def files_reload(config: KresConfig) -> None:
    cert_file = config.network.tls.cert_file
    key_file = config.network.tls.key_file

    if cert_file and key_file:
        logger.info("TLS cert files reload triggered")

        cmd = f"net.tls('{cert_file}', '{key_file}')"
        await command_registered_workers(cmd)
