import asyncio
import json

import httpx


async def main() -> None:
    base_url = "http://localhost:8080"
    binary_path = "./sample-binary/chargen"
    async with httpx.AsyncClient() as client:
        with open(binary_path, "rb") as handle:
            files = {"file": ("sample.bin", handle, "application/octet-stream")}
            response = await client.post(f"{base_url}/analyze/upload", files=files)
            response.raise_for_status()
        session_id = response.json()["session_id"]
        print("Session:", session_id)
        query = "Find suspicious API calls"
        await client.post(f"{base_url}/query", json={"session_id": session_id, "query": query})
        status = await client.get(f"{base_url}/status/{session_id}")
        print(json.dumps(status.json(), indent=2))


if __name__ == "__main__":
    asyncio.run(main())
