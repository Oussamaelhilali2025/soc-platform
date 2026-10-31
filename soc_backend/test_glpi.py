import asyncio
from app.services.glpi import GLPIService


async def main():
    service = GLPIService()

    result = await service.create_ticket(
        name="TEST SOC - Vulnerabilite Greenbone",
        content=(
            "Ticket de test cree depuis le portail SOC.\n\n"
            "Asset : Greenbone-Target-192.0.2.10\n"
            "IP : 192.0.2.10\n"
            "Severite : MEDIUM\n"
            "Source : Greenbone/OpenVAS"
        ),
        urgency=3,
    )

    print("GLPI TICKET CREATED:", result)


asyncio.run(main())