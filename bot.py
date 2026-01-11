import discord
from discord.ext import commands
import asyncio
from collections import defaultdict, deque
import time
import os
import aiohttp
import datetime
import json
import openai
from dotenv import load_dotenv
import io

load_dotenv()

# --- Bot Configuration ---
# Load the bot token from an environment variable for better security.
# You will need to create a .env file with the following line:
# DISCORD_BOT_TOKEN="YOUR_BOT_TOKEN"
# OPENROUTER_API_KEY="YOUR_OPENROUTER_API_KEY"
# OPENROUTER_MODEL="YOUR_OPENROUTER_MODEL"
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "mistralai/mistral-7b-instruct:free")

# --- AI Configuration ---
client = openai.OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=OPENROUTER_API_KEY,
)

# --- Intent Configuration ---
# The bot needs specific 'intents' to access certain events and data.
# For an anti-raid bot, it's crucial to have access to as much information as possible.
# We are enabling all default intents and the privileged 'members' and 'message_content' intents.
intents = discord.Intents.default()
intents.members = True  # Required to track member joins, removes, and updates.
intents.message_content = True  # Required to read message content for spam detection.

# --- Bot Client Initialization ---
bot = commands.Bot(command_prefix="/", intents=intents)

# --- Whitelist & Blacklist ---
WHITELIST_FILE = "whitelist.json"
BLACKLIST_FILE = "blacklist.json"
whitelist = set()
blacklist = set()
suspicious_messages = defaultdict(list)

def load_lists():
    """Loads the whitelist and blacklist from JSON files."""
    global whitelist, blacklist
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "r") as f:
            data = json.load(f)
            whitelist = set(data.get("whitelist", []))
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, "r") as f:
            data = json.load(f)
            blacklist = set(data.get("blacklist", []))

def save_whitelist():
    """Saves the whitelist to a JSON file."""
    with open(WHITELIST_FILE, "w") as f:
        json.dump({"whitelist": list(whitelist)}, f)

def save_blacklist():
    """Saves the blacklist to a JSON file."""
    with open(BLACKLIST_FILE, "w") as f:
        json.dump({"blacklist": list(blacklist)}, f)

# --- Spam Detection ---
SPAM_THRESHOLD = 20  # Number of messages
SPAM_TIMEFRAME = 10  # Seconds
user_message_times = defaultdict(lambda: deque(maxlen=SPAM_THRESHOLD))

# --- User Action Tracking ---
user_actions = defaultdict(lambda: defaultdict(list))
ACTION_TIMEFRAME = 10  # Seconds
CHANNEL_DELETE_THRESHOLD = 3
ROLE_DELETE_THRESHOLD = 3
ROLE_CREATE_THRESHOLD = 5
GUILD_UPDATE_THRESHOLD = 2
EMOJI_CREATE_THRESHOLD = 5
EMOJI_DELETE_THRESHOLD = 5
STICKER_CREATE_THRESHOLD = 5
STICKER_DELETE_THRESHOLD = 5
BAN_THRESHOLD = 5
KICK_THRESHOLD = 5
CHANNEL_CREATE_THRESHOLD = 5
CHANNEL_RENAME_THRESHOLD = 5
WEBHOOK_CREATE_THRESHOLD = 5
MEMBER_RENAME_THRESHOLD = 5
PERMISSION_ESCALATION_THRESHOLD = 1

# --- Raid Reporting ---
raid_reports = defaultdict(lambda: {
    'banned_users': 0,
    'unbanned_users': 0,
    'kicked_users': 0,
    'deleted_channels': 0,
    'created_channels': 0,
    'deleted_roles': 0,
    'created_roles': 0,
    'renamed_channels': 0,
    'renamed_members': 0,
    'deleted_emojis': 0,
    'deleted_stickers': 0,
    'deleted_webhooks': 0
})

async def get_audit_log_entry(guild, action, target_id):
    """Reliably fetches an audit log entry with retries."""
    for _ in range(5):
        async for entry in guild.audit_logs(action=action, limit=5):
            if entry.target.id == target_id:
                return entry
        await asyncio.sleep(1)
    return None

async def get_ai_analysis(raid_details):
    """Gets AI analysis of a raid event."""
    try:
        response = client.chat.completions.create(
            model=OPENROUTER_MODEL,
            messages=[
                {"role": "system", "content": "You are a security expert analyzing a Discord raid."},
                {"role": "user", "content": f"Analyze the following raid details and provide a summary and recommended actions:\n\n{raid_details}"},
            ],
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"Error getting AI analysis: {e}")
        return "Could not get AI analysis."

async def send_raid_alert(guild, user, reason):
    """
    Sends an alert to the server owner and a designated channel when a raid is detected.
    """
    owner = guild.owner
    embed = discord.Embed(
        title="🚨 Raid Action Detected 🚨",
        description=f"The anti-raid bot has taken action against a user.",
        color=discord.Color.red(),
        timestamp=datetime.datetime.utcnow()
    )
    embed.add_field(name="User Banned", value=f"{user.name}#{user.discriminator} ({user.id})", inline=False)
    embed.add_field(name="Reason", value=reason, inline=False)
    embed.set_footer(text="Anti-Raid Bot")

    # Get AI analysis
    raid_details = f"User: {user.name}#{user.discriminator} ({user.id})\nReason: {reason}\n\n**Raid Report:**\n"
    report = raid_reports[guild.id]
    for key, value in report.items():
        if value > 0:
            raid_details += f"- {key.replace('_', ' ').title()}: {value}\n"
    ai_analysis = await get_ai_analysis(raid_details)

    embed.add_field(name="AI Analysis", value=ai_analysis, inline=False)
    embed.add_field(name="Recommended Actions", value="No immediate actions required. The user has been banned and the server has been restored.", inline=False)

    # Send a DM to the server owner
    if owner:
        try:
            await owner.send(embed=embed)
        except discord.Forbidden:
            print(f"Could not send a DM to the server owner of '{guild.name}'.")

    # Send a message to a designated raid-alerts channel
    alert_channel = discord.utils.get(guild.text_channels, name="raid-logs-and-alerts")
    if alert_channel:
        try:
            await alert_channel.send(embed=embed)
        except discord.Forbidden:
            print(f"Could not send a message to the #raid-logs-and-alerts channel in '{guild.name}'.")

def is_unauthorized_actor(user, guild):
    """Checks if a user is an unauthorized actor."""
    return user and user != bot.user and user != guild.owner and user.id not in whitelist

# --- Data Caching ---
# This dictionary will store the structure of each server the bot is in.
# The key is the guild ID, and the value is a dictionary of server information.
server_cache = {}

async def cache_server_structure(guild):
    """
    Caches the structure of a given guild, including channels, roles, etc.
    """
    if guild.id not in server_cache:
        server_cache[guild.id] = {
            'name': guild.name,
            'icon': guild.icon.url if guild.icon else None,
            'channels': {},
            'roles': {},
            'emojis': {},
            'stickers': {}
        }

    # Cache channels
    for channel in guild.channels:
        server_cache[guild.id]['channels'][channel.id] = {
            'name': channel.name,
            'type': channel.type,
            'category_id': channel.category_id,
            'position': channel.position,
            'topic': getattr(channel, 'topic', None),
            'overwrites': {role.id: perm for role, perm in channel.overwrites.items()}
        }

    # Cache roles
    for role in guild.roles:
        server_cache[guild.id]['roles'][role.id] = {
            'name': role.name,
            'permissions': role.permissions,
            'color': role.color,
            'hoist': role.hoist,
            'mentionable': role.mentionable,
            'position': role.position,
            'members': [member.id for member in role.members]
        }

    # Cache emojis
    for emoji in guild.emojis:
        server_cache[guild.id]['emojis'][emoji.id] = {
            'name': emoji.name,
            'url': emoji.url,
            'animated': emoji.animated
        }

    # Cache stickers
    for sticker in guild.stickers:
        server_cache[guild.id]['stickers'][sticker.id] = {
            'name': sticker.name,
            'url': sticker.url,
            'description': sticker.description,
            'emoji': sticker.emoji
        }

# --- Event Handlers ---
@bot.event
async def on_ready():
    """
    This function is called when the bot successfully connects to Discord.
    """
    load_lists()
    print(f'Logged in as {bot.user.name} (ID: {bot.user.id})')
    print('------')
    for guild in bot.guilds:
        await cache_server_structure(guild)
        print(f'Cached server structure for {guild.name}')
    print('Anti-Raid Bot is online and ready to protect your server!')
    try:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} command(s)")
    except Exception as e:
        print(e)


@bot.event
async def on_guild_join(guild):
    """
    This function is called when the bot joins a new guild.
    """
    await cache_server_structure(guild)
    print(f'Joined and cached server structure for {guild.name}')

    # Create the raid-logs-and-alerts channel if it doesn't exist
    channel = discord.utils.get(guild.text_channels, name="raid-logs-and-alerts")
    if not channel:
        try:
            await guild.create_text_channel("raid-logs-and-alerts")
            print(f"Created #raid-logs-and-alerts channel in {guild.name}")
        except discord.Forbidden:
            print(f"Could not create #raid-logs-and-alerts channel in {guild.name}. Missing permissions.")

@bot.event
async def on_member_join(member):
    """Checks if a joining member is on the blacklist."""
    if member.id in blacklist:
        await member.ban(reason="Blacklisted user.")
        print(f"Banned blacklisted user {member.name}.")

@bot.event
async def on_guild_channel_delete(channel):
    """
    This function is called when a channel is deleted.
    """
    guild = channel.guild
    entry = await get_audit_log_entry(guild, discord.AuditLogAction.channel_delete, channel.id)

    if is_unauthorized_actor(entry.user, guild):
        user = entry.user
        current_time = time.time()

        user_actions[user.id]['channel_delete'].append((current_time, channel.id))

        # Immediately restore the deleted channel
        cached_channel_info = server_cache.get(guild.id, {}).get('channels', {}).get(channel.id)
        if cached_channel_info:
            try:
                category = guild.get_channel(cached_channel_info['category_id']) if cached_channel_info.get('category_id') else None
                overwrites = {}
                for role_id, perms in cached_channel_info.get('overwrites', {}).items():
                    role = guild.get_role(role_id)
                    if role:
                        overwrites[role] = perms

                recreated_channel = None
                channel_type = cached_channel_info['type']

                if channel_type == discord.ChannelType.text:
                    recreated_channel = await guild.create_text_channel(
                        name=cached_channel_info['name'],
                        category=category,
                        topic=cached_channel_info.get('topic'),
                        position=cached_channel_info['position'],
                        overwrites=overwrites
                    )
                elif channel_type == discord.ChannelType.voice:
                    recreated_channel = await guild.create_voice_channel(
                        name=cached_channel_info['name'],
                        category=category,
                        position=cached_channel_info['position'],
                        overwrites=overwrites
                    )
                elif channel_type == discord.ChannelType.category:
                    recreated_channel = await guild.create_category(
                        name=cached_channel_info['name'],
                        position=cached_channel_info['position'],
                        overwrites=overwrites
                    )

                if recreated_channel:
                    print(f"Recreated channel '{recreated_channel.name}' in '{guild.name}'.")
                    raid_reports[guild.id]['deleted_channels'] += 1

            except discord.Forbidden:
                print(f"Could not restore channel '{cached_channel_info['name']}'. Missing permissions.")
            except discord.HTTPException as e:
                print(f"Failed to restore channel '{cached_channel_info['name']}': {e}")

        # Check if the user has reached the threshold for banning
        if len(user_actions[user.id]['channel_delete']) >= CHANNEL_DELETE_THRESHOLD:
            print(f"Banning {user.name} for deleting multiple channels.")
            try:
                await guild.ban(user, reason="Mass channel deletion.")
                blacklist.add(user.id)
                save_blacklist()
                raid_reports[guild.id]['banned_users'] += 1
                await send_raid_alert(guild, user, "Mass channel deletion.")
                user_actions[user.id]['channel_delete'] = []
            except discord.Forbidden:
                print(f"Could not ban {user.name}. Missing permissions.")
            except discord.HTTPException as e:
                print(f"Failed to ban {user.name}: {e}")

@bot.event
async def on_guild_channel_create(channel):
    """
    This function is called when a channel is created, to keep the cache updated.
    """
    guild = channel.guild
    entry = await get_audit_log_entry(guild, discord.AuditLogAction.channel_create, channel.id)

    if is_unauthorized_actor(entry.user, guild):
        user = entry.user
        current_time = time.time()
        user_actions[user.id]['channel_create'] = [item for item in user_actions[user.id]['channel_create'] if current_time - item[0] < ACTION_TIMEFRAME]
        user_actions[user.id]['channel_create'].append((current_time, channel.id))

        if len(user_actions[user.id]['channel_create']) >= CHANNEL_CREATE_THRESHOLD:
            print(f"Banning {user.name} for creating multiple channels.")
            try:
                await guild.ban(user, reason="Mass channel creation.")
                blacklist.add(user.id)
                save_blacklist()
                # Delete the extra channels
                channels_to_delete = [item[1] for item in user_actions[user.id]['channel_create']]
                for channel_id in channels_to_delete:
                    ch = guild.get_channel(channel_id)
                    if ch:
                        await ch.delete()
                raid_reports[guild.id]['created_channels'] += len(channels_to_delete)
                user_actions[user.id]['channel_create'] = [] # Clear actions after handling
            except discord.Forbidden:
                print(f"Could not ban {user.name} or delete channels. Missing permissions.")
            except discord.HTTPException as e:
                print(f"Failed to ban {user.name} or delete channels: {e}")
            else:
                raid_reports[guild.id]['banned_users'] += 1
                await send_raid_alert(guild, user, "Mass channel creation.")
        else:
            if guild.id in server_cache:
                server_cache[guild.id]['channels'][channel.id] = {
                    'name': channel.name,
                    'type': channel.type,
                    'category_id': channel.category_id,
                    'position': channel.position,
                    'topic': getattr(channel, 'topic', None),
                    'overwrites': {role.id: perm for role, perm in channel.overwrites.items()}
                }
                print(f"Cached new channel '{channel.name}' in '{guild.name}'.")

@bot.event
async def on_guild_channel_update(before, after):
    """
    This function is called when a channel is updated, to keep the cache updated.
    """
    guild = after.guild
    if before.name != after.name:
        entry = await get_audit_log_entry(guild, discord.AuditLogAction.channel_update, after.id)

        if is_unauthorized_actor(entry.user, guild):
            user = entry.user
            current_time = time.time()
            user_actions[user.id]['channel_rename'] = [item for item in user_actions[user.id]['channel_rename'] if current_time - item[0] < ACTION_TIMEFRAME]
            user_actions[user.id]['channel_rename'].append((current_time, after.id))

            if len(user_actions[user.id]['channel_rename']) >= CHANNEL_RENAME_THRESHOLD:
                print(f"Banning {user.name} for renaming multiple channels.")
                try:
                    await guild.ban(user, reason="Mass channel renaming.")
                    blacklist.add(user.id)
                    save_blacklist()
                except discord.Forbidden:
                    print(f"Could not ban {user.name}. Missing permissions.")
                except discord.HTTPException as e:
                    print(f"Failed to ban {user.name}: {e}")
                else:
                    raid_reports[guild.id]['banned_users'] += 1
                    await send_raid_alert(guild, user, "Mass channel renaming.")

            # Revert the channel name
            cached_channel_info = server_cache.get(guild.id, {}).get('channels', {}).get(after.id)
            if cached_channel_info and cached_channel_info['name'] != after.name:
                try:
                    await after.edit(name=cached_channel_info['name'])
                    print(f"Reverted channel name for '{after.name}'.")
                    raid_reports[guild.id]['renamed_channels'] += 1
                except discord.Forbidden:
                    print(f"Could not revert channel name for '{after.name}'. Missing permissions.")
        else:
            if guild.id in server_cache:
                server_cache[guild.id]['channels'][after.id] = {
                    'name': after.name,
                    'type': after.type,
                    'category_id': after.category_id,
                    'position': after.position,
                    'topic': getattr(after, 'topic', None),
                    'overwrites': {role.id: perm for role, perm in after.overwrites.items()}
                }
                print(f"Updated cached channel '{after.name}' in '{guild.name}'.")
    else:
        if guild.id in server_cache:
            server_cache[guild.id]['channels'][after.id] = {
                'name': after.name,
                'type': after.type,
                'category_id': after.category_id,
                'position': after.position,
                'topic': getattr(after, 'topic', None),
                'overwrites': {role.id: perm for role, perm in after.overwrites.items()}
            }
            print(f"Updated cached channel '{after.name}' in '{guild.name}'.")

@bot.event
async def on_guild_update(before, after):
    """
    This function is called when the guild is updated (e.g., name change).
    """
    guild = after
    cached_server_info = server_cache.get(guild.id, {})

    # --- Raid Detection & Banning ---
    entry = await get_audit_log_entry(guild, discord.AuditLogAction.guild_update, guild.id)

    if is_unauthorized_actor(entry.user, guild):
        user = entry.user
        current_time = time.time()

        user_actions[user.id]['guild_update'] = [t for t in user_actions[user.id]['guild_update'] if current_time - t < ACTION_TIMEFRAME]
        user_actions[user.id]['guild_update'].append(current_time)

        if len(user_actions[user.id]['guild_update']) >= GUILD_UPDATE_THRESHOLD:
            print(f"Banning {user.name} for multiple server updates.")
            try:
                await guild.ban(user, reason="Mass server updates.")
                blacklist.add(user.id)
                save_blacklist()
            except discord.Forbidden:
                print(f"Could not ban {user.name}. Missing permissions.")
            except discord.HTTPException as e:
                print(f"Failed to ban {user.name}: {e}")
            else:
                raid_reports[guild.id]['banned_users'] += 1
                await send_raid_alert(guild, user, "Mass server updates.")

        # --- Server Restoration ---
        if before.name != after.name:
            try:
                await after.edit(name=cached_server_info.get('name', before.name))
                print(f"Reverted server name to '{cached_server_info.get('name', before.name)}'.")
                raid_reports[guild.id]['renamed_server'] = 1
            except discord.Forbidden:
                print("Could not revert server name. Missing permissions.")

        if before.icon != after.icon:
            # Icon restoration is more complex and requires downloading and uploading the icon.
            # This is left as a potential future improvement.
            print(f"Server icon change detected. Manual restoration may be required.")

@bot.event
async def on_webhooks_update(channel):
    """
    This function is called when a webhook is created, updated, or deleted.
    """
    guild = channel.guild
    entry = await get_audit_log_entry(guild, discord.AuditLogAction.webhook_create, channel.id)

    if is_unauthorized_actor(entry.user, guild):
        user = entry.user
        current_time = time.time()
        user_actions[user.id]['webhook_create'] = [t for t in user_actions[user.id]['webhook_create'] if current_time - t < ACTION_TIMEFRAME]
        user_actions[user.id]['webhook_create'].append(current_time)

        if len(user_actions[user.id]['webhook_create']) >= WEBHOOK_CREATE_THRESHOLD:
            print(f"Banning {user.name} for creating multiple webhooks.")
            try:
                await guild.ban(user, reason="Mass webhook creation.")
                blacklist.add(user.id)
                save_blacklist()
            except discord.Forbidden:
                print(f"Could not ban {user.name}. Missing permissions.")
            except discord.HTTPException as e:
                print(f"Failed to ban {user.name}: {e}")
            else:
                raid_reports[guild.id]['banned_users'] += 1
                await send_raid_alert(guild, user, "Mass webhook creation.")

@bot.event
async def on_message(message):
    """
    This function is called when a message is sent.
    """
    if message.webhook_id:
        # Advanced webhook spam detection
        if "@everyone" in message.content:
            user_actions[message.webhook_id]['webhook_spam'].append(time.time())
            if len(user_actions[message.webhook_id]['webhook_spam']) >= 5:
                try:
                    webhook = await bot.fetch_webhook(message.webhook_id)
                    await webhook.delete(reason="Webhook spamming @everyone")
                    print(f"Deleted webhook {webhook.name} for spamming @everyone.")
                    raid_reports[message.guild.id]['deleted_webhooks'] += 1
                    # Ban the creator of the webhook
                    entry = None
                    async for e in message.guild.audit_logs(action=discord.AuditLogAction.webhook_create, limit=10):
                        if e.target.id == message.webhook_id:
                            entry = e
                            break
                    if entry and entry.user:
                        await message.guild.ban(entry.user, reason="Created a webhook that spammed @everyone.")
                        blacklist.add(entry.user.id)
                        save_blacklist()
                except (discord.NotFound, discord.Forbidden):
                    pass

        current_time = time.time()
        user_message_times[message.webhook_id].append(current_time)

        if len(user_message_times[message.webhook_id]) == SPAM_THRESHOLD:
            if current_time - user_message_times[message.webhook_id][0] < SPAM_TIMEFRAME:
                try:
                    webhook = await bot.fetch_webhook(message.webhook_id)
                    await webhook.delete(reason="Spamming")
                    print(f"Deleted webhook {webhook.name} for spamming.")
                    raid_reports[message.guild.id]['deleted_webhooks'] += 1
                except (discord.NotFound, discord.Forbidden):
                    pass # Webhook might already be deleted
        return

    if message.author.bot:
        return

    # Suspicious message sniping
    if any(keyword in message.content.lower() for keyword in [".nuke", ".raid"]):
        suspicious_messages[message.guild.id].append(f"[{message.created_at}] {message.author}: {message.content}")

    current_time = time.time()
    user_message_times[message.author.id].append(current_time)

    # Check for spam
    if len(user_message_times[message.author.id]) == SPAM_THRESHOLD:
        if current_time - user_message_times[message.author.id][0] < SPAM_TIMEFRAME:
            try:
                await message.author.ban(reason="Spamming")
                blacklist.add(message.author.id)
                save_blacklist()
                print(f"Banned {message.author} for spamming.")
                # Optionally, delete the spam messages
                await message.channel.purge(limit=SPAM_THRESHOLD, check=lambda m: m.author == message.author)
            except discord.Forbidden:
                print(f"Could not ban {message.author}. Missing permissions.")
            except discord.HTTPException as e:
                print(f"Failed to ban {message.author}: {e}")
            else:
                await send_raid_alert(message.guild, message.author, "Spamming.")

@bot.event
async def on_guild_role_create(role):
    """
    This function is called when a role is created.
    """
    guild = role.guild
    # --- Raid Detection & Banning ---
    entry = await get_audit_log_entry(guild, discord.AuditLogAction.role_create, role.id)

    if is_unauthorized_actor(entry.user, guild):
        # Check for duplicate roles
        for r in guild.roles:
            if r.name == role.name and r.id != role.id:
                await role.delete()
                print(f"Deleted duplicate role '{role.name}'.")
                return

        user = entry.user
        current_time = time.time()

        user_actions[user.id]['role_create'] = [item for item in user_actions[user.id]['role_create'] if current_time - item[0] < ACTION_TIMEFRAME]
        user_actions[user.id]['role_create'].append((current_time, role.id))

        if len(user_actions[user.id]['role_create']) >= ROLE_CREATE_THRESHOLD:
            print(f"Banning {user.name} for creating multiple roles.")
            try:
                await guild.ban(user, reason="Mass role creation.")
                blacklist.add(user.id)
                save_blacklist()
                # Delete the extra roles
                roles_to_delete = [item[1] for item in user_actions[user.id]['role_create']]
                for role_id in roles_to_delete:
                    r = guild.get_role(role_id)
                    if r:
                        await r.delete()
                raid_reports[guild.id]['created_roles'] += len(roles_to_delete)
                user_actions[user.id]['role_create'] = [] # Clear actions after handling
            except discord.Forbidden:
                print(f"Could not ban {user.name} or delete roles. Missing permissions.")
            except discord.HTTPException as e:
                print(f"Failed to ban {user.name} or delete roles: {e}")
            else:
                raid_reports[guild.id]['banned_users'] += 1
                await send_raid_alert(guild, user, "Mass role creation.")
        else:
            # Update cache after checks
            if guild.id in server_cache:
                server_cache[guild.id]['roles'][role.id] = {
                    'name': role.name,
                    'permissions': role.permissions,
                    'color': role.color,
                    'hoist': role.hoist,
                    'mentionable': role.mentionable,
                    'position': role.position,
                    'members': [member.id for member in role.members]
                }
                print(f"Cached new role '{role.name}' in '{guild.name}'.")

@bot.event
async def on_guild_role_update(before, after):
    """
    This function is called when a role is updated, to keep the cache updated.
    """
    guild = after.guild
    entry = await get_audit_log_entry(guild, discord.AuditLogAction.role_update, after.id)

    if is_unauthorized_actor(entry.user, guild):
        # Malicious update, revert and don't update cache
        try:
            await after.edit(
                name=before.name,
                permissions=before.permissions,
                color=before.color,
                hoist=before.hoist,
                mentionable=before.mentionable,
                position=before.position
            )
            print(f"Reverted role update for '{after.name}'.")
        except discord.Forbidden:
            print(f"Could not revert role update for '{after.name}'. Missing permissions.")
    else:
        # Legitimate update, update cache
        if guild.id in server_cache:
            server_cache[guild.id]['roles'][after.id] = {
                'name': after.name,
                'permissions': after.permissions,
                'color': after.color,
                'hoist': after.hoist,
                'mentionable': after.mentionable,
                'position': after.position,
                'members': [member.id for member in after.members]
            }
            print(f"Updated cached role '{after.name}' in '{guild.name}'.")

@bot.event
async def on_guild_role_delete(role):
    """
    This function is called when a role is deleted.
    """
    guild = role.guild
    cached_role_info = server_cache.get(guild.id, {}).get('roles', {}).get(role.id)

    if not cached_role_info:
        print(f"Deleted role '{role.name}' not found in cache.")
        return

    # --- Raid Detection & Banning ---
    entry = await get_audit_log_entry(guild, discord.AuditLogAction.role_delete, role.id)

    if is_unauthorized_actor(entry.user, guild):
        user = entry.user
        current_time = time.time()

        user_actions[user.id]['role_delete'] = [item for item in user_actions[user.id]['role_delete'] if current_time - item[0] < ACTION_TIMEFRAME]
        user_actions[user.id]['role_delete'].append((current_time, role.id))

        if len(user_actions[user.id]['role_delete']) >= ROLE_DELETE_THRESHOLD:
            print(f"Banning {user.name} for deleting multiple roles.")
            try:
                await guild.ban(user, reason="Mass role deletion.")
                blacklist.add(user.id)
                save_blacklist()
            except discord.Forbidden:
                print(f"Could not ban {user.name}. Missing permissions.")
            except discord.HTTPException as e:
                print(f"Failed to ban {user.name}: {e}")
            else:
                raid_reports[guild.id]['banned_users'] += 1
                await send_raid_alert(guild, user, "Mass role deletion.")

    # --- Role Restoration ---
    try:
        recreated_role = await guild.create_role(
            name=cached_role_info['name'],
            permissions=cached_role_info['permissions'],
            color=cached_role_info['color'],
            hoist=cached_role_info['hoist'],
            mentionable=cached_role_info['mentionable']
        )
        print(f"Recreated role '{recreated_role.name}' in '{guild.name}'.")
        raid_reports[guild.id]['deleted_roles'] += 1

        # Re-assign the role to the original members who are still in the server
        for member_id in cached_role_info.get('members', []):
            member = guild.get_member(member_id)
            if member and member in guild.members:
                try:
                    await member.add_roles(recreated_role)
                except discord.Forbidden:
                    print(f"Could not add role '{recreated_role.name}' to {member.name}. Missing permissions.")
                except discord.HTTPException as e:
                    print(f"Failed to add role '{recreated_role.name}' to {member.name}: {e}")
    except discord.Forbidden:
        print(f"Could not restore role '{cached_role_info['name']}'. Missing permissions.")
    except discord.HTTPException as e:
        print(f"Failed to restore role '{cached_role_info['name']}': {e}")

@bot.event
async def on_member_update(before, after):
    """
    This function is called when a member is updated (e.g., nickname change).
    """
    guild = after.guild
    # --- Permission Escalation Detection ---
    if not before.guild_permissions.administrator and after.guild_permissions.administrator:
        entry = await get_audit_log_entry(guild, discord.AuditLogAction.member_role_update, after.id)

        if is_unauthorized_actor(entry.user, guild):
            actor = entry.user
            print(f"Banning {actor.name} and {after.name} for permission escalation.")
            try:
                await guild.ban(actor, reason="Permission escalation.")
                blacklist.add(actor.id)
                await guild.ban(after, reason="Permission escalation.")
                blacklist.add(after.id)
                save_blacklist()
                await after.remove_roles(*[role for role in after.roles if role.permissions.administrator])
            except discord.Forbidden:
                print("Could not ban users or remove roles. Missing permissions.")
            except discord.HTTPException as e:
                print(f"Failed to ban users or remove roles: {e}")
            else:
                raid_reports[guild.id]['banned_users'] += 2
                await send_raid_alert(guild, actor, "Permission escalation.")
                await send_raid_alert(guild, after, "Permission escalation.")

    # --- Mass Member Renaming Protection ---
    if before.nick != after.nick:
        entry = await get_audit_log_entry(guild, discord.AuditLogAction.member_update, after.id)

        if is_unauthorized_actor(entry.user, guild):
            user = entry.user
            current_time = time.time()
            user_actions[user.id]['member_rename'] = [item for item in user_actions[user.id]['member_rename'] if current_time - item[0] < ACTION_TIMEFRAME]
            user_actions[user.id]['member_rename'].append((current_time, after.id))

            if len(user_actions[user.id]['member_rename']) >= MEMBER_RENAME_THRESHOLD:
                print(f"Banning {user.name} for renaming multiple members.")
                try:
                    await guild.ban(user, reason="Mass member renaming.")
                    blacklist.add(user.id)
                    save_blacklist()
                    # Revert the nicknames of all affected members
                    members_to_revert = [item[1] for item in user_actions[user.id]['member_rename']]
                    for member_id in members_to_revert:
                        member = guild.get_member(member_id)
                        if member:
                            try:
                                await member.edit(nick=None) # Reset to default username
                                raid_reports[guild.id]['renamed_members'] += 1
                            except discord.Forbidden:
                                print(f"Could not revert nickname for '{member.name}'. Missing permissions.")
                    user_actions[user.id]['member_rename'] = []
                except discord.Forbidden:
                    print(f"Could not ban {user.name}. Missing permissions.")
                except discord.HTTPException as e:
                    print(f"Failed to ban {user.name}: {e}")
                else:
                    raid_reports[guild.id]['banned_users'] += 1
                    await send_raid_alert(guild, user, "Mass member renaming.")
            else:
                # Revert the nickname
                try:
                    await after.edit(nick=before.nick)
                    print(f"Reverted nickname for '{after.name}'.")
                    raid_reports[guild.id]['renamed_members'] += 1
                except discord.Forbidden:
                    print(f"Could not revert nickname for '{after.name}'. Missing permissions.")

@bot.event
async def on_member_ban(guild, user):
    """
    This function is called when a member is banned.
    """
    entry = await get_audit_log_entry(guild, discord.AuditLogAction.ban, user.id)

    if is_unauthorized_actor(entry.user, guild):
        actor = entry.user
        current_time = time.time()
        user_actions[actor.id]['ban'] = [item for item in user_actions[actor.id]['ban'] if current_time - item[0] < ACTION_TIMEFRAME]
        user_actions[actor.id]['ban'].append((current_time, user.id))

        if len(user_actions[actor.id]['ban']) >= BAN_THRESHOLD:
            print(f"Banning {actor.name} for mass banning.")
            try:
                await guild.ban(actor, reason="Mass banning.")
                blacklist.add(actor.id)
                save_blacklist()
                # Unban the users who were banned by the raider
                users_to_unban = [item[1] for item in user_actions[actor.id]['ban']]
                for user_id in users_to_unban:
                    banned_user = await bot.fetch_user(user_id)
                    await guild.unban(banned_user)
                raid_reports[guild.id]['unbanned_users'] += len(users_to_unban)
                user_actions[actor.id]['ban'] = [] # Clear actions after handling
            except discord.Forbidden:
                print(f"Could not ban {actor.name}. Missing permissions.")
            except discord.HTTPException as e:
                print(f"Failed to ban {actor.name}: {e}")
            else:
                raid_reports[guild.id]['banned_users'] += 1
                await send_raid_alert(guild, actor, "Mass banning.")

@bot.event
async def on_member_remove(member):
    """
    This function is called when a member is removed (kicked or leaves).
    """
    guild = member.guild
    entry = await get_audit_log_entry(guild, discord.AuditLogAction.kick, member.id)

    if is_unauthorized_actor(entry.user, guild):
        actor = entry.user
        current_time = time.time()
        user_actions[actor.id]['kick'] = [item for item in user_actions[actor.id]['kick'] if current_time - item[0] < ACTION_TIMEFRAME]
        user_actions[actor.id]['kick'].append((current_time, member.id))

        if len(user_actions[actor.id]['kick']) >= KICK_THRESHOLD:
            print(f"Banning {actor.name} for mass kicking.")
            try:
                await guild.ban(actor, reason="Mass kicking.")
                blacklist.add(actor.id)
                save_blacklist()
            except discord.Forbidden:
                print(f"Could not ban {actor.name}. Missing permissions.")
            except discord.HTTPException as e:
                print(f"Failed to ban {actor.name}: {e}")
            else:
                raid_reports[guild.id]['banned_users'] += 1
                await send_raid_alert(guild, actor, "Mass kicking.")

@bot.event
async def on_guild_emojis_update(guild, before, after):
    """
    This function is called when emojis are updated in a guild.
    """
    # Find created emojis
    created_emojis = [emoji for emoji in after if emoji not in before]
    if created_emojis:
        for emoji in created_emojis:
            for e in guild.emojis:
                if e.name == emoji.name and e.id != emoji.id:
                    await emoji.delete()
                    print(f"Deleted duplicate emoji '{emoji.name}'.")
                    return

    # Find deleted emojis
    deleted_emojis = [emoji for emoji in before if emoji not in after]
    if deleted_emojis:
        # For simplicity, we'll only check the audit log for the first deleted emoji
        emoji = deleted_emojis[0]
        entry = await get_audit_log_entry(guild, discord.AuditLogAction.emoji_delete, emoji.id)

        if is_unauthorized_actor(entry.user, guild):
            user = entry.user
            current_time = time.time()
            user_actions[user.id]['emoji_delete'] = [item for item in user_actions[user.id]['emoji_delete'] if current_time - item[0] < ACTION_TIMEFRAME]
            user_actions[user.id]['emoji_delete'].append((current_time, emoji.id))

            if len(user_actions[user.id]['emoji_delete']) >= EMOJI_DELETE_THRESHOLD:
                print(f"Banning {user.name} for deleting multiple emojis.")
                try:
                    await guild.ban(user, reason="Mass emoji deletion.")
                    blacklist.add(user.id)
                    save_blacklist()
                except discord.Forbidden:
                    print(f"Could not ban {user.name}. Missing permissions.")
                except discord.HTTPException as e:
                    print(f"Failed to ban {user.name}: {e}")
                else:
                    raid_reports[guild.id]['banned_users'] += 1
                    await send_raid_alert(guild, user, "Mass emoji deletion.")

        # Restore deleted emojis
        async with aiohttp.ClientSession() as session:
            for emoji in deleted_emojis:
                cached_emoji_info = server_cache.get(guild.id, {}).get('emojis', {}).get(emoji.id)
                if cached_emoji_info:
                    try:
                        async with session.get(cached_emoji_info['url']) as resp:
                            if resp.status == 200:
                                image_bytes = await resp.read()
                                await guild.create_custom_emoji(name=cached_emoji_info['name'], image=image_bytes)
                                print(f"Restored emoji '{emoji.name}'.")
                                raid_reports[guild.id]['deleted_emojis'] += 1
                                await asyncio.sleep(1) # Prevent rate-limiting
                    except (discord.Forbidden, discord.HTTPException) as e:
                        print(f"Failed to restore emoji '{emoji.name}': {e}")

    # Update cache
    server_cache[guild.id]['emojis'] = {emoji.id: {'name': emoji.name, 'url': emoji.url, 'animated': emoji.animated} for emoji in after}

@bot.event
async def on_guild_stickers_update(guild, before, after):
    """
    This function is called when stickers are updated in a guild.
    """
    # Find created stickers
    created_stickers = [sticker for sticker in after if sticker not in before]
    if created_stickers:
        for sticker in created_stickers:
            for s in guild.stickers:
                if s.name == sticker.name and s.id != sticker.id:
                    await sticker.delete()
                    print(f"Deleted duplicate sticker '{sticker.name}'.")
                    return

    deleted_stickers = [sticker for sticker in before if sticker not in after]
    if deleted_stickers:
        sticker = deleted_stickers[0]
        entry = await get_audit_log_entry(guild, discord.AuditLogAction.sticker_delete, sticker.id)

        if is_unauthorized_actor(entry.user, guild):
            user = entry.user
            current_time = time.time()
            user_actions[user.id]['sticker_delete'] = [item for item in user_actions[user.id]['sticker_delete'] if current_time - item[0] < ACTION_TIMEFRAME]
            user_actions[user.id]['sticker_delete'].append((current_time, sticker.id))

            if len(user_actions[user.id]['sticker_delete']) >= STICKER_DELETE_THRESHOLD:
                print(f"Banning {user.name} for deleting multiple stickers.")
                try:
                    await guild.ban(user, reason="Mass sticker deletion.")
                    blacklist.add(user.id)
                    save_blacklist()
                except discord.Forbidden:
                    print(f"Could not ban {user.name}. Missing permissions.")
                except discord.HTTPException as e:
                    print(f"Failed to ban {user.name}: {e}")
                else:
                    raid_reports[guild.id]['banned_users'] += 1
                    await send_raid_alert(guild, user, "Mass sticker deletion.")

        async with aiohttp.ClientSession() as session:
            for sticker in deleted_stickers:
                cached_sticker_info = server_cache.get(guild.id, {}).get('stickers', {}).get(sticker.id)
                if cached_sticker_info:
                    try:
                        async with session.get(cached_sticker_info['url']) as resp:
                            if resp.status == 200:
                                image_bytes = await resp.read()
                                await guild.create_sticker(name=cached_sticker_info['name'], description=cached_sticker_info['description'], emoji=cached_sticker_info['emoji'], file=discord.File(io.BytesIO(image_bytes)))
                                print(f"Restored sticker '{sticker.name}'.")
                                raid_reports[guild.id]['deleted_stickers'] += 1
                                await asyncio.sleep(1) # Prevent rate-limiting
                    except (discord.Forbidden, discord.HTTPException) as e:
                        print(f"Failed to restore sticker '{sticker.name}': {e}")

    server_cache[guild.id]['stickers'] = {sticker.id: {'name': sticker.name, 'url': sticker.url, 'description': sticker.description, 'emoji': sticker.emoji} for sticker in after}

# --- Whitelist & Blacklist Commands ---
@bot.tree.command(name="whitelist", description="Add a user to the whitelist.")
@commands.has_permissions(administrator=True)
async def whitelist_command(interaction: discord.Interaction, user: discord.User):
    """Adds a user to the whitelist."""
    if user.id in whitelist:
        await interaction.response.send_message(f"{user.name} is already whitelisted.")
    else:
        whitelist.add(user.id)
        save_whitelist()
        await interaction.response.send_message(f"{user.name} has been added to the whitelist.")

@bot.tree.command(name="unwhitelist", description="Remove a user from the whitelist.")
@commands.has_permissions(administrator=True)
async def unwhitelist_command(interaction: discord.Interaction, user: discord.User):
    """Removes a user from the whitelist."""
    if user.id not in whitelist:
        await interaction.response.send_message(f"{user.name} is not whitelisted.")
    else:
        whitelist.remove(user.id)
        save_whitelist()
        await interaction.response.send_message(f"{user.name} has been removed from the whitelist.")

@bot.tree.command(name="unblacklist", description="Remove a user from the blacklist.")
@commands.has_permissions(administrator=True)
async def unblacklist_command(interaction: discord.Interaction, user_id: str):
    """Removes a user from the blacklist."""
    try:
        user_id = int(user_id)
        if user_id not in blacklist:
            await interaction.response.send_message(f"{user_id} is not blacklisted.")
        else:
            blacklist.remove(user_id)
            save_blacklist()
            await interaction.response.send_message(f"{user_id} has been removed from the blacklist.")
    except ValueError:
        await interaction.response.send_message("Invalid user ID.")

@bot.tree.command(name="refresh", description="Refresh the server's cached structure.")
@commands.has_permissions(administrator=True)
async def refresh_command(interaction: discord.Interaction):
    """Refreshes the server's cached structure."""
    await interaction.response.defer()
    await cache_server_structure(interaction.guild)
    await interaction.followup.send("Server cache has been refreshed.")

@bot.tree.command(name="raidreport", description="Get a report of the bot's anti-raid actions.")
@commands.has_permissions(administrator=True)
async def raidreport_command(interaction: discord.Interaction):
    """Gets a report of the bot's anti-raid actions."""
    report = raid_reports[interaction.guild.id]
    embed = discord.Embed(
        title="Raid Activity Report",
        color=discord.Color.orange()
    )
    embed.add_field(name="Banned Users", value=report['banned_users'], inline=True)
    embed.add_field(name="Unbanned Users", value=report['unbanned_users'], inline=True)
    embed.add_field(name="Kicked Users", value=report['kicked_users'], inline=True)
    embed.add_field(name="Deleted Channels", value=report['deleted_channels'], inline=True)
    embed.add_field(name="Created Channels", value=report['created_channels'], inline=True)
    embed.add_field(name="Deleted Roles", value=report['deleted_roles'], inline=True)
    embed.add_field(name="Created Roles", value=report['created_roles'], inline=True)
    embed.add_field(name="Renamed Channels", value=report['renamed_channels'], inline=True)
    embed.add_field(name="Renamed Members", value=report['renamed_members'], inline=True)
    embed.add_field(name="Deleted Emojis", value=report['deleted_emojis'], inline=True)
    embed.add_field(name="Deleted Stickers", value=report['deleted_stickers'], inline=True)
    embed.add_field(name="Deleted Webhooks", value=report['deleted_webhooks'], inline=True)

    # Add suspicious messages to the report
    if suspicious_messages[interaction.guild.id]:
        with open("suspicious_messages.txt", "w") as f:
            for msg in suspicious_messages[interaction.guild.id]:
                f.write(f"{msg}\n")
        await interaction.response.send_message(embed=embed, file=discord.File("suspicious_messages.txt"))
        os.remove("suspicious_messages.txt")
        suspicious_messages[interaction.guild.id] = []
    else:
        await interaction.response.send_message(embed=embed)

    raid_reports.pop(interaction.guild.id, None)

# --- Main Execution ---
if __name__ == "__main__":
    if not BOT_TOKEN:
        print("Error: The bot token is not set. Please create a .env file and set DISCORD_BOT_TOKEN.")
    else:
        bot.run(BOT_TOKEN)
