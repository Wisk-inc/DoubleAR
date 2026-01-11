# Anti-Raid Discord Bot

This is a Python-based Discord bot designed to protect your server from raids.

## Features

- **Channel Protection:** Automatically recreates deleted channels.
- **Role Protection:** Automatically recreates deleted roles and re-assigns them to members.
- **Spam Detection:** Automatically bans users who spam messages.
- **Server Protection:** Automatically reverts unauthorized changes to the server's name and icon.
- **Raid Reporting:** Provides a summary report of actions taken during a raid.

## Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/your-repository-name.git
    cd your-repository-name
    ```

2.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Set up the bot token:**
    - Rename the `.env.example` file to `.env`.
    - Open the `.env` file and replace `"YOUR_BOT_TOKEN"` with your actual Discord bot token.

4.  **Run the bot:**
    ```bash
    python bot.py
    ```

## Production Considerations

This bot is a proof-of-concept and has a few limitations that should be addressed before deploying it to a production environment:

-   **In-Memory Cache:** The bot's server cache is stored in memory, which means it will be lost if the bot restarts. For a production-ready bot, this should be replaced with a persistent storage solution, such as a database or a file-based cache.

-   **Hardcoded Whitelist:** Currently, only the server owner is exempt from the bot's anti-raid actions. In a real-world scenario, you would want to have a configurable whitelist of trusted users or roles who are allowed to perform mass actions.

-   **Single-File Structure:** The bot's logic is contained in a single `bot.py` file. For better maintainability, this should be refactored into multiple files or by using the `discord.py` Cogs extension.