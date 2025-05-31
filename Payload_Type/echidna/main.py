#!/usr/bin/env python3

import asyncio
from mythic_container import mythic_container
from echidna.builder import Echidna

mythic_container.mythic_service.add_payload_type(Echidna())

async def main():
    await mythic_container.start_and_run_forever()

if __name__ == "__main__":
    asyncio.run(main())