import hashlib
import struct
import sys
from asyncio import Event, run, sleep
from dataclasses import dataclass

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload_dataclass import DataClassPayload, type_from_format
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver
from ipv8.util import run_forever
from ipv8_service import IPv8

COMMUNITY_ID = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")
SERVER_PUBLIC_KEY = bytes.fromhex(
    "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb"
    # "4c69624e61434c504b3ae822fef1a3397d5e97c341e6770a15a5be0e93629920dc9fd84d72beb961a91a34ceefff29e4f65e52cd1a41c66486da6b749c70c947389601970582f802ab04"
)
EMAIL = "pgomesmoreira@tudelft.nl"
GITHUB_URL = "https://github.com/pedrogmo/BlockchainLab"
DIFFICULTY = 28

varlenHutf8 = type_from_format("varlenHutf8")

@dataclass
class SubmissionPayload(DataClassPayload[1]):
    email: str
    github_url: str
    nonce: int


@dataclass
class ResponsePayload(DataClassPayload[2]):
    success: bool
    message: str


def mine_nonce(email: str, github_url: str, difficulty: int) -> int:
    """Brute-force search for a valid nonce."""
    nonce = 0

    if difficulty == 28:
        nonce = 481538558 # Pre-mined for 28 bits

    email_utf8 = email.encode("utf-8")
    github_url_utf8 = github_url.encode("utf-8")

    while True:
        nonce_bytes = struct.pack(">Q", nonce)
        data = email_utf8 + b"\n" + github_url_utf8 + b"\n" + nonce_bytes
        hash_bytes = hashlib.sha256(data).digest()

        zero_bytes = difficulty // 8
        remaining_zeros = difficulty % 8

        failed = False
        i = 0
        while i < zero_bytes:
            if hash_bytes[i] != 0:
                failed = True
                break
            i += 1

        if failed:
            nonce += 1
            continue

        if hash_bytes[i] < (1 << (8 - remaining_zeros)):
            return nonce

        # if hash_bytes[0] == 0 and hash_bytes[1] == 0 and hash_bytes[2] == 0 and hash_bytes[3] < 16:
        #     return nonce

        nonce += 1

class LabCommunity(Community, PeerObserver):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.add_message_handler(ResponsePayload, self.on_response)
        self.add_message_handler(SubmissionPayload, self.on_response_submission)

        self.email = settings.email
        self.github_url = settings.github_url

    def on_peer_added(self, peer: Peer) -> None:
        print("I am:", self.my_peer, "I found:", peer)
        print(f"Their key is {peer.public_key.key_to_bin().hex()}")

    def on_peer_removed(self, peer: Peer) -> None:
        pass

    def started(self) -> None:
        self.network.add_peer_observer(self)

        self.register_task("find_server", self.find_server, delay=5.0, interval=10.0)

        print("MY KEY")
        print(self.my_peer.public_key.key_to_bin().hex())

    def find_server(self):
        print("Trying to find server...")
        # 1. Search peers for server by matching public key
        for peer in self.get_peers():
            print(f"Peer {peer}")
            if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
                print("Found the server")
                # 2. Mine a valid nonce for (email, github_url)
                nonce = mine_nonce(self.email, self.github_url, DIFFICULTY)

                # 3. Send SubmissionPayload to server via ez_send
                payload = SubmissionPayload(self.email, self.github_url, nonce)
                self.ez_send(peer, payload)

    @lazy_wrapper(ResponsePayload)
    def on_response(self, peer: Peer, payload: ResponsePayload) -> None:
        """Handle server response (message_id=2)."""
        if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
            print(payload)

            if payload.success:
                print("Server ACCEPTED the submission")
            else:
                print("Server REJECTED the submission")

            sys.exit(0)

    @lazy_wrapper(SubmissionPayload)
    def on_response_submission(self, peer: Peer, payload: ResponsePayload) -> None:
        """Handle server response (message_id=1)."""
        print(f"Got submission from peer {peer}: \n{payload}")


async def start_community() -> None:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key(EMAIL, "curve25519", "pedro.pem")
    builder.add_overlay(
        "LabCommunity",
        EMAIL,
        [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
        default_bootstrap_defs,
        {
            "email": EMAIL,
            "github_url": GITHUB_URL,
        },
        [("started",)],
    )
    ipv8 = IPv8(builder.finalize(), extra_communities={"LabCommunity": LabCommunity})
    await ipv8.start()
    await run_forever()



run(start_community())
