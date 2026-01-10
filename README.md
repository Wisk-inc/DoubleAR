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