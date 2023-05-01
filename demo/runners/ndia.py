import asyncio
import json
import logging
import os
import sys
import time
import datetime

from aiohttp import ClientError
from qrcode import QRCode

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runners.agent_container import (  # noqa:E402
    arg_parser,
    create_agent_with_args,
    AriesAgent,
)
from runners.support.agent import (  # noqa:E402
    CRED_FORMAT_INDY,
    CRED_FORMAT_JSON_LD,
    SIG_TYPE_BLS,
)
from runners.support.utils import (  # noqa:E402
    log_msg,
    log_status,
    prompt,
    prompt_loop,
)


CRED_PREVIEW_TYPE = "https://didcomm.org/issue-credential/2.0/credential-preview"
SELF_ATTESTED = os.getenv("SELF_ATTESTED")
TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class NdiaAgent(AriesAgent):
    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        no_auto: bool = False,
        endorser_role: str = None,
        revocation: bool = False,
        **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="Ndia",
            no_auto=no_auto,
            endorser_role=endorser_role,
            revocation=revocation,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}
        # TODO define a dict to hold credential attributes
        # based on cred_def_id
        self.cred_attrs = {}

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    def generate_credential_offer(self, aip, cred_type, cred_def_id, exchange_tracing):
        age = 24
        d = datetime.date.today()
        birth_date = datetime.date(d.year - age, d.month, d.day)
        birth_date_format = "%Y%m%d"
        if aip == 10:
            # define attributes to send for credential
            self.cred_attrs[cred_def_id] = {
                    "first_name": "Alice",
                    "last_name": "Smith",
                    "job_code": str(int(8765)),
                    "date": "2023-04-28",
                    "timestamp": str(int(time.time())),
            }

            cred_preview = {
                "@type": CRED_PREVIEW_TYPE,
                "attributes": [
                    {"name": n, "value": v}
                    for (n, v) in self.cred_attrs[cred_def_id].items()
                ],
            }
            offer_request = {
                "connection_id": self.connection_id,
                "cred_def_id": cred_def_id,
                "comment": f"Offer on cred def id {cred_def_id}",
                "auto_remove": False,
                "credential_preview": cred_preview,
                "trace": exchange_tracing,
            }
            return offer_request


        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")

    def generate_proof_request_web_request(
        self, aip, cred_type, revocation, exchange_tracing, connectionless=False
    ):
        j_code = 8765
        d = datetime.date.today()
        if aip == 10:
            req_attrs = [
                {
                    "name": "first_name",
                    "restrictions": [{"schema_name": "cv schema"}],
                },
                                {
                    "name": "last_name",
                    "restrictions": [{"schema_name": "cv schema"}],
                },
            ]
            if revocation:
                req_attrs.append(
                    {
                        "name": "last_name",
                        "restrictions": [{"schema_name": "cv schema"}],
                        "non_revoked": {"to": int(time.time() - 1)},
                    },
                )
            else:
                req_attrs.append(
                    {
                        "name": "last_name",
                        "restrictions": [{"schema_name": "cv schema"}],
                    }
                )
            if SELF_ATTESTED:
                # test self-attested claims
                req_attrs.append(
                    {"name": "self_attested_thing"},
                )
            req_preds = [
                # test zero-knowledge proofs
                {
                    "name": "job_code",
                    "p_type": ">=",
                    "p_value": j_code,
                    "restrictions": [{"schema_name": "cv schema"}],
                }
            ]
            indy_proof_request = {
                "name": "Proof of Qualifications",
                "version": "1.0",
                "requested_attributes": {
                    f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
                },
                "requested_predicates": {
                    f"0_{req_pred['name']}_GE_uuid": req_pred for req_pred in req_preds
                },
            }

            if revocation:
                indy_proof_request["non_revoked"] = {"to": int(time.time())}

            proof_request_web_request = {
                "proof_request": indy_proof_request,
                "trace": exchange_tracing,
            }
            if not connectionless:
                proof_request_web_request["connection_id"] = self.connection_id
            return proof_request_web_request


        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")


async def main(args):
    ndia_agent = await create_agent_with_args(args, ident="ndia")

    try:
        log_status(
            "#1 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {ndia_agent.wallet_type})"
                if ndia_agent.wallet_type
                else ""
            )
        )
        agent = NdiaAgent(
            "ndia.agent",
            ndia_agent.start_port,
            ndia_agent.start_port + 1,
            genesis_data=ndia_agent.genesis_txns,
            genesis_txn_list=ndia_agent.genesis_txn_list,
            no_auto=ndia_agent.no_auto,
            tails_server_base_url=ndia_agent.tails_server_base_url,
            revocation=ndia_agent.revocation,
            timing=ndia_agent.show_timing,
            multitenant=ndia_agent.multitenant,
            mediation=ndia_agent.mediation,
            wallet_type=ndia_agent.wallet_type,
            seed=ndia_agent.seed,
            aip=ndia_agent.aip,
            endorser_role=ndia_agent.endorser_role,
        )

        ndia_schema_name = "cv schema"
        ndia_schema_attrs = [
            "first_name",
            "last_name",
            "job_code",
            "date",
            "timestamp",
        ]
        if ndia_agent.cred_type == CRED_FORMAT_INDY:
            ndia_agent.public_did = True
            await ndia_agent.initialize(
                the_agent=agent,
                schema_name=ndia_schema_name,
                schema_attrs=ndia_schema_attrs,
                create_endorser_agent=(ndia_agent.endorser_role == "author")
                if ndia_agent.endorser_role
                else False,
            )
        elif ndia_agent.cred_type == CRED_FORMAT_JSON_LD:
            ndia_agent.public_did = True
            await ndia_agent.initialize(the_agent=agent)
        else:
            raise Exception("Invalid credential type:" + ndia_agent.cred_type)

        # generate an invitation for Alice
        await ndia_agent.generate_invitation(
            display_qr=True, reuse_connections=ndia_agent.reuse_connections, wait=True
        )

        exchange_tracing = False
        options = (
            "    (1) Issue Credential\n"
            "    (2) Send Proof Request\n"
            "    (2a) Send *Connectionless* Proof Request (requires a Mobile client)\n"
            "    (3) Send Message\n"
            "    (4) Create New Invitation\n"
        )
        if ndia_agent.revocation:
            options += "    (5) Revoke Credential\n" "    (6) Publish Revocations\n"
        if ndia_agent.endorser_role and ndia_agent.endorser_role == "author":
            options += "    (D) Set Endorser's DID\n"
        if ndia_agent.multitenant:
            options += "    (W) Create and/or Enable Wallet\n"
        options += "    (T) Toggle tracing on credential/proof exchange\n"
        options += "    (X) Exit?\n[1/2/3/4/{}{}T/X] ".format(
            "5/6/" if ndia_agent.revocation else "",
            "W/" if ndia_agent.multitenant else "",
        )
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option in "dD" and ndia_agent.endorser_role:
                endorser_did = await prompt("Enter Endorser's DID: ")
                await ndia_agent.agent.admin_POST(
                    f"/transactions/{ndia_agent.agent.connection_id}/set-endorser-info",
                    params={"endorser_did": endorser_did},
                )

            elif option in "wW" and ndia_agent.multitenant:
                target_wallet_name = await prompt("Enter wallet name: ")
                include_subwallet_webhook = await prompt(
                    "(Y/N) Create sub-wallet webhook target: "
                )
                if include_subwallet_webhook.lower() == "y":
                    created = await ndia_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        webhook_port=ndia_agent.agent.get_new_webhook_port(),
                        public_did=True,
                        mediator_agent=ndia_agent.mediator_agent,
                        endorser_agent=ndia_agent.endorser_agent,
                        taa_accept=ndia_agent.taa_accept,
                    )
                else:
                    created = await ndia_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        public_did=True,
                        mediator_agent=ndia_agent.mediator_agent,
                        endorser_agent=ndia_agent.endorser_agent,
                        cred_type=ndia_agent.cred_type,
                        taa_accept=ndia_agent.taa_accept,
                    )
                # create a schema and cred def for the new wallet
                # TODO check first in case we are switching between existing wallets
                if created:
                    # TODO this fails because the new wallet doesn't get a public DID
                    await ndia_agent.create_schema_and_cred_def(
                        schema_name=ndia_schema_name,
                        schema_attrs=ndia_schema_attrs,
                    )

            elif option in "tT":
                exchange_tracing = not exchange_tracing
                log_msg(
                    ">>> Credential/Proof Exchange Tracing is {}".format(
                        "ON" if exchange_tracing else "OFF"
                    )
                )

            elif option == "1":
                log_status("#13 Issue credential offer to X")

                if ndia_agent.aip == 10:
                    offer_request = ndia_agent.agent.generate_credential_offer(
                        ndia_agent.aip, None, ndia_agent.cred_def_id, exchange_tracing
                    )
                    await ndia_agent.agent.admin_POST(
                        "/issue-credential/send-offer", offer_request
                    )

                else:
                    raise Exception(f"Error invalid AIP level: {ndia_agent.aip}")

            elif option == "2":
                log_status("#20 Request proof of qualifications from alice")
                if ndia_agent.aip == 10:
                    proof_request_web_request = (
                        ndia_agent.agent.generate_proof_request_web_request(
                            ndia_agent.aip,
                            ndia_agent.cred_type,
                            ndia_agent.revocation,
                            exchange_tracing,
                        )
                    )
                    await ndia_agent.agent.admin_POST(
                        "/present-proof/send-request", proof_request_web_request
                    )
                    pass

                else:
                    raise Exception(f"Error invalid AIP level: {ndia_agent.aip}")

            elif option == "2a":
                log_status("#20 Request * Connectionless * proof of degree from alice")
                if ndia_agent.aip == 10:
                    proof_request_web_request = (
                        ndia_agent.agent.generate_proof_request_web_request(
                            ndia_agent.aip,
                            ndia_agent.cred_type,
                            ndia_agent.revocation,
                            exchange_tracing,
                            connectionless=True,
                        )
                    )
                    proof_request = await ndia_agent.agent.admin_POST(
                        "/present-proof/create-request", proof_request_web_request
                    )
                    pres_req_id = proof_request["presentation_exchange_id"]
                    url = (
                        os.getenv("WEBHOOK_TARGET")
                        or (
                            "http://"
                            + os.getenv("DOCKERHOST").replace(
                                "{PORT}", str(ndia_agent.agent.admin_port + 1)
                            )
                            + "/webhooks"
                        )
                    ) + f"/pres_req/{pres_req_id}/"
                    log_msg(f"Proof request url: {url}")
                    qr = QRCode(border=1)
                    qr.add_data(url)
                    log_msg(
                        "Scan the following QR code to accept the proof request from a mobile agent."
                    )
                    qr.print_ascii(invert=True)

                else:
                    raise Exception(f"Error invalid AIP level: {ndia_agent.aip}")

            elif option == "3":
                msg = await prompt("Enter message: ")
                await ndia_agent.agent.admin_POST(
                    f"/connections/{ndia_agent.agent.connection_id}/send-message",
                    {"content": msg},
                )

            elif option == "4":
                log_msg(
                    "Creating a new invitation, please receive "
                    "and accept this invitation using Alice agent"
                )
                await ndia_agent.generate_invitation(
                    display_qr=True,
                    reuse_connections=ndia_agent.reuse_connections,
                    wait=True,
                )

            elif option == "5" and ndia_agent.revocation:
                rev_reg_id = (await prompt("Enter revocation registry ID: ")).strip()
                cred_rev_id = (await prompt("Enter credential revocation ID: ")).strip()
                publish = (
                    await prompt("Publish now? [Y/N]: ", default="N")
                ).strip() in "yY"
                try:
                    await ndia_agent.agent.admin_POST(
                        "/revocation/revoke",
                        {
                            "rev_reg_id": rev_reg_id,
                            "cred_rev_id": cred_rev_id,
                            "publish": publish,
                            "connection_id": ndia_agent.agent.connection_id,
                            # leave out thread_id, let aca-py generate
                            # "thread_id": "12345678-4444-4444-4444-123456789012",
                            "comment": "Revocation reason goes here ...",
                        },
                    )
                except ClientError:
                    pass

            elif option == "6" and ndia_agent.revocation:
                try:
                    resp = await ndia_agent.agent.admin_POST(
                        "/revocation/publish-revocations", {}
                    )
                    ndia_agent.agent.log(
                        "Published revocations for {} revocation registr{} {}".format(
                            len(resp["rrid2crid"]),
                            "y" if len(resp["rrid2crid"]) == 1 else "ies",
                            json.dumps([k for k in resp["rrid2crid"]], indent=4),
                        )
                    )
                except ClientError:
                    pass

        if ndia_agent.show_timing:
            timing = await ndia_agent.agent.fetch_timing()
            if timing:
                for line in ndia_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await ndia_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="ndia", port=8020)
    args = parser.parse_args()

    ENABLE_PYDEVD_PYCHARM = os.getenv("ENABLE_PYDEVD_PYCHARM", "").lower()
    ENABLE_PYDEVD_PYCHARM = ENABLE_PYDEVD_PYCHARM and ENABLE_PYDEVD_PYCHARM not in (
        "false",
        "0",
    )
    PYDEVD_PYCHARM_HOST = os.getenv("PYDEVD_PYCHARM_HOST", "localhost")
    PYDEVD_PYCHARM_CONTROLLER_PORT = int(
        os.getenv("PYDEVD_PYCHARM_CONTROLLER_PORT", 5001)
    )

    if ENABLE_PYDEVD_PYCHARM:
        try:
            import pydevd_pycharm

            print(
                "Ndia remote debugging to "
                f"{PYDEVD_PYCHARM_HOST}:{PYDEVD_PYCHARM_CONTROLLER_PORT}"
            )
            pydevd_pycharm.settrace(
                host=PYDEVD_PYCHARM_HOST,
                port=PYDEVD_PYCHARM_CONTROLLER_PORT,
                stdoutToServer=True,
                stderrToServer=True,
                suspend=False,
            )
        except ImportError:
            print("pydevd_pycharm library was not found")

    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)