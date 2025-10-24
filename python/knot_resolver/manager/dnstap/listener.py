import asyncio
import logging
from pathlib import Path

from knot_resolver.constants import FSTRM_LIB, PROTOBUF_LIB
from knot_resolver.manager.config_store import ConfigStore
from knot_resolver.utils import compat

logger = logging.getLogger(__name__)


if FSTRM_LIB and PROTOBUF_LIB:
    import fstrm  # type: ignore[import-untyped]

    from knot_resolver.manager.dnstap import dnstap_pb2

    async def callback(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peername = writer.get_extra_info("peername")
        if not len(peername):
            peername = "(unix-socket)"
        logger.info(f"New connection from {peername}")

        content_type = b"protobuf:dnstap.Dnstap"
        fstrm_handler = fstrm.FstrmCodec()
        # loop = asyncio.get_event_loop()
        dnstap_protobuf = dnstap_pb2.Dnstap()  # type: ignore[attr-defined]

        try:
            running = True
            while running:
                read_task = asyncio.create_task(reader.read(fstrm_handler.pending_nb_bytes()))
                data = await read_task
                if not len(data):
                    running = False
                    break

                # append data to the buffer
                fstrm_handler.append(data=data)

                # process the buffer, check if we have received a complete frame ?
                if fstrm_handler.process():
                    # Ok, the frame is complete so let's decode it
                    ctrl, ct, payload = fstrm_handler.decode()

                    # handle the DATA frame
                    if ctrl == fstrm.FSTRM_DATA_FRAME:
                        dnstap_protobuf.ParseFromString(payload)
                        dm = dnstap_protobuf.message
                        logger.debug(dm)

                    # handle the control frame READY
                    if ctrl == fstrm.FSTRM_CONTROL_READY:
                        if content_type not in ct:
                            raise Exception("content type error: %s" % ct)

                        # todo, checking content type
                        ctrl_accept = fstrm_handler.encode(ctrl=fstrm.FSTRM_CONTROL_ACCEPT, ct=[content_type])
                        # respond with accept only if the content type is dnstap
                        writer.write(ctrl_accept)
                        await writer.drain()

                    # handle the control frame STOP
                    if ctrl == fstrm.FSTRM_CONTROL_STOP:
                        fstrm_handler.reset()

                        # send finish control
                        ctrl_finish = fstrm_handler.encode(ctrl=fstrm.FSTRM_CONTROL_FINISH)
                        writer.write(ctrl_finish)
                        await writer.drain()

        except asyncio.IncompleteReadError:
            pass
        except ConnectionError:
            writer.close()
        except asyncio.CancelledError:
            writer.close()
            await writer.wait_closed()

    async def start_dnstap_listener(socket_path: Path) -> None:
        if socket_path.exists():
            socket_path.unlink()

        server = await asyncio.start_unix_server(callback, path=socket_path)
        logger.info(f"Listening dnstap on '{socket_path}'")

        async with server:
            await server.serve_forever()


async def init_dnstap_listener(config_store: ConfigStore) -> None:
    config = config_store.get()
    if FSTRM_LIB and PROTOBUF_LIB and config.logging.dnstap:
        socket_path = config.logging.dnstap.unix_socket.to_path()
        if compat.asyncio.is_event_loop_running():
            compat.asyncio.create_task(start_dnstap_listener(socket_path))
        else:
            compat.asyncio.run(start_dnstap_listener(socket_path))
