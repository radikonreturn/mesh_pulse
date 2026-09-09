import asyncio

from mesh_pulse.app import MeshPulseApp


async def main():
    app = MeshPulseApp()
    async with app.run_test() as pilot:
        print("Pressing 's'")
        await pilot.press("s")
        await asyncio.sleep(0.5)
        print("Checking screen")
        print(app.screen.id or app.screen)


if __name__ == "__main__":
    asyncio.run(main())
