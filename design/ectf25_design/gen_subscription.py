import argparse
import json
import struct
from loguru import logger
from cryptography.hazmat.primitives import hashes


def gen_subscription(secrets: bytes, device_id: int, start: int, end: int, channel: int) -> bytes:
    """Generate the contents of a subscription."""
    secrets = json.loads(secrets)

    # Secure subscription data with encryption or hashing
    subscription_data = struct.pack("<IQQI", device_id, start, end, channel)

    # Securely signing the subscription data
    hashed_sub = hashes.SHA256(subscription_data).digest()

    # Packing the subscription with the hashed value for verification
    return struct.pack("<IQQI32s", device_id, start, end, channel, hashed_sub)


def parse_args():
    """Define and parse the command line arguments

    NOTE: Your design must not change this function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of subscription file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=argparse.FileType("rb"),
        help="Path to the secrets file created by ectf25_design.gen_secrets",
    )
    parser.add_argument("subscription_file", type=Path, help="Subscription output")
    parser.add_argument(
        "device_id", type=lambda x: int(x, 0), help="Device ID of the update recipient."
    )
    parser.add_argument(
        "start", type=lambda x: int(x, 0), help="Subscription start timestamp"
    )
    parser.add_argument("end", type=int, help="Subscription end timestamp")
    parser.add_argument("channel", type=int, help="Channel to subscribe to")
    return parser.parse_args()


def main():
    """Main function of gen_subscription
    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    subscription = gen_subscription(
        args.secrets_file.read(), args.device_id, args.start, args.end, args.channel
    )

    # Print the generated subscription for your own debugging
    # Attackers will NOT have access to the output of this (although they may have
    # subscriptions in certain scenarios), but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    logger.debug(f"Generated subscription: {subscription}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.subscription_file, "wb" if args.force else "xb") as f:
        f.write(subscription)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote subscription to {str(args.subscription_file.absolute())}")


if __name__ == "__main__":
    main()
