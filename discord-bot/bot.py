#!/usr/bin/env python3
"""
Discord "Verified Builder" bot (T2).
"""
import os
import json
import discord
from discord.ext import commands
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# Load configuration from environment
BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN")
VERIFIED_ROLE_NAME = "Verified Builder"


def verify_receipt(receipt: dict, trusted_keys: list) -> tuple[bool, str]:
    """
    Verify a receipt offline against the trusted keys.
    Returns (ok, reason).
    """
    if not isinstance(receipt, dict):
        return False, "malformed receipt: not a JSON object"

    # Route 1: Studio receipts (Formats 2-4)
    sb = receipt.get("signature")
    if isinstance(sb, dict) and sb.get("sig"):
        # 1. Pick integrity = first present of integrity_hash / integrity / integrity_root
        ih_field = next((k for k in ("integrity_hash", "integrity", "integrity_root") if receipt.get(k)), None)
        if not ih_field:
            return False, "malformed: missing integrity field"
        
        integrity = receipt[ih_field]
        sig = sb.get("sig")
        key_id = sb.get("key_id")
        if not sig or not key_id:
            return False, "malformed: missing signature sig or key_id"
            
        # 2. Find the trusted key whose key_id matches
        trusted_key = next((tk for tk in trusted_keys if tk.get("key_id") == key_id), None)
        if not trusted_key:
            return False, "unknown signer"
            
        # 3. Ed25519-verify sig over str(integrity).encode('utf-8')
        try:
            pub_hex = trusted_key.get("public_key_hex")
            if not pub_hex:
                return False, "trusted key missing public_key_hex"
            public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
            public_key.verify(bytes.fromhex(sig), str(integrity).encode("utf-8"))
            return True, f"signed by {key_id}"
        except InvalidSignature:
            return False, "signature invalid"
        except Exception as e:
            return False, f"verification error: {str(e)}"

    # Route 2: CLI audit receipts (Format 1)
    sig_hex = receipt.get("signature_hex")
    pub_hex = receipt.get("public_key_hex")
    if sig_hex and pub_hex:
        # Check if pub_hex is in our trusted keys
        trusted_key = next((tk for tk in trusted_keys if tk.get("public_key_hex") == pub_hex), None)
        if not trusted_key:
            return False, "unknown signer"
            
        key_id = trusted_key.get("key_id", pub_hex[:16])
        try:
            # Reconstruct signed payload by stripping metadata keys
            body = {k: v for k, v in receipt.items() if k not in ("signer_alg", "public_key_hex", "signature_hex")}
            # Deterministic serialization (canonical JSON)
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            
            public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
            public_key.verify(bytes.fromhex(sig_hex), canonical)
            return True, f"signed by {key_id}"
        except InvalidSignature:
            return False, "signature invalid"
        except Exception as e:
            return False, f"verification error: {str(e)}"

    return False, "unrecognized receipt format"


def load_trusted_keys() -> list:
    p = os.environ.get("RAILCALL_TRUSTED_KEYS")
    if not p or not os.path.isfile(p):
        # Fall back to standard user-level / install workspaces
        home = os.path.expanduser("~")
        candidate_paths = [
            os.path.join(home, ".railcall", "signing_pubkey.json"),
            os.path.join(home, ".railcall", "station", ".railcall_workspace", "signing_pubkey.json"),
            os.path.join(home, ".railcall", ".railcall_workspace", "signing_pubkey.json"),
        ]
        for cp in candidate_paths:
            if os.path.isfile(cp):
                p = cp
                break

    if p and os.path.isfile(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                doc = json.load(f)
                if isinstance(doc, list):
                    return doc
                elif isinstance(doc, dict):
                    return [doc]
        except Exception:
            pass
    return []


# intents
intents = discord.Intents.default()
intents.message_content = True  # Required to read receipt attachments
bot = commands.Bot(command_prefix="!", intents=intents)


@bot.event
async def on_ready():
    print(f"Logged in as {bot.user.name} (ID: {bot.user.id})")
    print("------")


@bot.event
async def on_message(message):
    if message.author.bot:
        return

    # Check if the message has a JSON attachment
    for attachment in message.attachments:
        if attachment.filename.endswith(".json"):
            try:
                file_bytes = await attachment.read()
                receipt = json.loads(file_bytes.decode("utf-8"))
                
                # Check if it has a RailCall schema
                if isinstance(receipt, dict) and "schema" in receipt:
                    trusted_keys = load_trusted_keys()
                    ok, reason = verify_receipt(receipt, trusted_keys)
                    if ok:
                        role = discord.utils.get(message.guild.roles, name=VERIFIED_ROLE_NAME)
                        if not role:
                            role = await message.guild.create_role(name=VERIFIED_ROLE_NAME, color=discord.Color.green())
                        await message.author.add_roles(role)
                        await message.channel.send(
                            f"✅ **SUCCESS**: {message.author.mention} has submitted a valid cryptographic receipt!\n"
                            f"Awarded role: **{VERIFIED_ROLE_NAME}**.\n"
                            f"Details: `{reason}`"
                        )
                    else:
                        await message.channel.send(
                            f"❌ **INVALID RECEIPT**: Verification failed for `{attachment.filename}`.\n"
                            f"Reason: `{reason}`"
                        )
            except Exception as e:
                await message.channel.send(f"⚠️ Error processing receipt: `{str(e)}`")

    await bot.process_commands(message)


if __name__ == "__main__":
    if not BOT_TOKEN:
        print("ERROR: DISCORD_BOT_TOKEN is not set in the environment.")
    else:
        bot.run(BOT_TOKEN)
