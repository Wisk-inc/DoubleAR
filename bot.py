import discord
import asyncio
from collections import defaultdict, deque
import time
import os

# --- Bot Configuration ---
# Load the bot token from an environment variable for better security.
# You will need to create a .env file with the following line:
# DISCORD_BOT_TOKEN="YOUR_BOT_TOKEN"
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")

# --- Intent Configuration ---
# The bot needs specific 'intents' to access certain events and data.
# For an anti-raid bot, it's crucial to have access to as much information as possible.
# We are enabling all default intents and the privileged 'members' and 'message_content' intents.
intents = discord.Intents.default()
intents.members = True  # Required to track member joins, removes, and updates.
intents.message_content = True  # Required to read message content for spam detection.

# --- Bot Client Initialization ---
client = discord.Client(intents=intents)

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

# --- Raid Reporting ---
raid_reports = defaultdict(lambda: {
    'banned_users': 0,
    'restored_channels': 0,
    'restored_roles': 0,
    'recovered_messages': 0
})

# --- Data Caching ---
# This dictionary will store the structure of each server the bot is in.
# The key is the guild ID, and the value is a dictionary of server information.
server_cache = {}
message_cache = defaultdict(lambda: deque(maxlen=100)) # Cache last 100 messages per channel

async def cache_server_structure(guild):
    """
    Caches the structure of a given guild, including channels, roles, etc.
    """
    if guild.id not in server_cache:
        server_cache[guild.id] = {
            'name': guild.name,
            'icon': guild.icon.url if guild.icon else None,
            'channels': {},
            'roles': {}
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

# --- Event Handlers ---
@client.event
async def on_ready():
    """
    This function is called when the bot successfully connects to Discord.
    """
    print(f'Logged in as {client.user.name} (ID: {client.user.id})')
    print('------')
    for guild in client.guilds:
        await cache_server_structure(guild)
        print(f'Cached server structure for {guild.name}')
    print('Anti-Raid Bot is online and ready to protect your server!')

@client.event
async def on_guild_join(guild):
    """
    This function is called when the bot joins a new guild.
    """
    await cache_server_structure(guild)
    print(f'Joined and cached server structure for {guild.name}')

@client.event
async def on_guild_channel_delete(channel):
    """
    This function is called when a channel is deleted.
    """
    guild = channel.guild
    cached_channel_info = server_cache.get(guild.id, {}).get('channels', {}).get(channel.id)

    if not cached_channel_info:
        print(f"Deleted channel '{channel.name}' not found in cache.")
        return

    # --- Raid Detection & Banning ---
    # Check the audit log to find who deleted the channel.
    # We add a small delay to ensure the audit log is updated.
    await asyncio.sleep(2)

    entry = None
    async for e in guild.audit_logs(action=discord.AuditLogAction.channel_delete, limit=1):
        if e.target.id == channel.id:
            entry = e
            break

    if entry and entry.user:
        user = entry.user
        current_time = time.time()

        # Clean up old actions
        user_actions[user.id]['channel_delete'] = [t for t in user_actions[user.id]['channel_delete'] if current_time - t < ACTION_TIMEFRAME]

        # Record new action
        user_actions[user.id]['channel_delete'].append(current_time)

        # Check if threshold is exceeded
        if len(user_actions[user.id]['channel_delete']) >= CHANNEL_DELETE_THRESHOLD:
            print(f"Banning {user.name} for deleting multiple channels.")
            try:
                await guild.ban(user, reason="Mass channel deletion.")
            except discord.Forbidden:
                print(f"Could not ban {user.name}. Missing permissions.")
            except discord.HTTPException as e:
                print(f"Failed to ban {user.name}: {e}")
            else:
                raid_reports[guild.id]['banned_users'] += 1

    # --- Channel Restoration ---
    category = guild.get_channel(cached_channel_info['category_id']) if cached_channel_info['category_id'] else None

    # --- Channel Restoration ---
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
        raid_reports[guild.id]['restored_channels'] += 1

    # --- Message Restoration ---
    if channel.id in message_cache:
        restored_count = 0
        for msg in message_cache[channel.id]:
            embed = discord.Embed(
                description=msg.content,
                timestamp=msg.created_at
            )
            embed.set_author(name=msg.author.name, icon_url=msg.author.avatar.url if msg.author.avatar else None)
            if msg.attachments:
                embed.set_image(url=msg.attachments[0].url)

            try:
                await recreated_channel.send(embed=embed)
                restored_count += 1
            except discord.HTTPException:
                pass # Ignore if the message can't be sent
        print(f"Restored {restored_count} messages to '{recreated_channel.name}'.")
        raid_reports[guild.id]['recovered_messages'] += restored_count
        del message_cache[channel.id]

@client.event
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
    await asyncio.sleep(2)
    entry = None
    async for e in guild.audit_logs(action=discord.AuditLogAction.role_delete, limit=1):
        if e.target.id == role.id:
            entry = e
            break

    if entry and entry.user:
        user = entry.user
        current_time = time.time()

        user_actions[user.id]['role_delete'] = [t for t in user_actions[user.id]['role_delete'] if current_time - t < ACTION_TIMEFRAME]
        user_actions[user.id]['role_delete'].append(current_time)

        if len(user_actions[user.id]['role_delete']) >= ROLE_DELETE_THRESHOLD:
            print(f"Banning {user.name} for deleting multiple roles.")
            try:
                await guild.ban(user, reason="Mass role deletion.")
            except discord.Forbidden:
                print(f"Could not ban {user.name}. Missing permissions.")
            except discord.HTTPException as e:
                print(f"Failed to ban {user.name}: {e}")
            else:
                raid_reports[guild.id]['banned_users'] += 1

    # --- Role Restoration ---
    recreated_role = await guild.create_role(
        name=cached_role_info['name'],
        permissions=cached_role_info['permissions'],
        color=cached_role_info['color'],
        hoist=cached_role_info['hoist'],
        mentionable=cached_role_info['mentionable']
    )
    print(f"Recreated role '{recreated_role.name}' in '{guild.name}'.")
    raid_reports[guild.id]['restored_roles'] += 1

    # Re-assign the role to the original members
    for member_id in cached_role_info.get('members', []):
        member = guild.get_member(member_id)
        if member:
            try:
                await member.add_roles(recreated_role)
            except discord.Forbidden:
                print(f"Could not add role '{recreated_role.name}' to {member.name}. Missing permissions.")
            except discord.HTTPException as e:
                print(f"Failed to add role '{recreated_role.name}' to {member.name}: {e}")

@client.event
async def on_guild_channel_create(channel):
    """
    This function is called when a channel is created, to keep the cache updated.
    """
    guild = channel.guild
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

@client.event
async def on_guild_channel_update(before, after):
    """
    This function is called when a channel is updated, to keep the cache updated.
    """
    guild = after.guild
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

@client.event
async def on_guild_update(before, after):
    """
    This function is called when the guild is updated (e.g., name change).
    """
    guild = after
    cached_server_info = server_cache.get(guild.id, {})

    # --- Raid Detection & Banning ---
    await asyncio.sleep(2)
    entry = None
    async for e in guild.audit_logs(action=discord.AuditLogAction.guild_update, limit=1):
        entry = e
        break

    if entry and entry.user:
        user = entry.user
        current_time = time.time()

        user_actions[user.id]['guild_update'] = [t for t in user_actions[user.id]['guild_update'] if current_time - t < ACTION_TIMEFRAME]
        user_actions[user.id]['guild_update'].append(current_time)

        if len(user_actions[user.id]['guild_update']) >= GUILD_UPDATE_THRESHOLD:
            print(f"Banning {user.name} for multiple server updates.")
            try:
                await guild.ban(user, reason="Mass server updates.")
            except discord.Forbidden:
                print(f"Could not ban {user.name}. Missing permissions.")
            except discord.HTTPException as e:
                print(f"Failed to ban {user.name}: {e}")
            else:
                raid_reports[guild.id]['banned_users'] += 1

        # --- Server Restoration ---
        if before.name != after.name:
            try:
                await after.edit(name=cached_server_info.get('name', before.name))
                print(f"Reverted server name to '{cached_server_info.get('name', before.name)}'.")
            except discord.Forbidden:
                print("Could not revert server name. Missing permissions.")

        if before.icon != after.icon:
            # Icon restoration is more complex and requires downloading and uploading the icon.
            # This is left as a potential future improvement.
            print(f"Server icon change detected. Manual restoration may be required.")


@client.event
async def on_message(message):
    """
    This function is called when a message is sent.
    """
    if message.author.bot:
        return

    if message.content == '!raidreport':
        report = raid_reports[message.guild.id]
        embed = discord.Embed(
            title="Raid Activity Report",
            color=discord.Color.orange()
        )
        embed.add_field(name="Banned Users", value=report['banned_users'], inline=False)
        embed.add_field(name="Restored Channels", value=report['restored_channels'], inline=False)
        embed.add_field(name="Restored Roles", value=report['restored_roles'], inline=False)
        embed.add_field(name="Recovered Messages", value=report['recovered_messages'], inline=False)

        try:
            await message.channel.send(embed=embed)
        except discord.Forbidden:
            print(f"Could not send raid report to {message.channel.name}. Missing permissions.")

        # Reset the report for the guild
        raid_reports[message.guild.id] = defaultdict(int)

    message_cache[message.channel.id].append(message)

    current_time = time.time()
    user_message_times[message.author.id].append(current_time)

    # Check for spam
    if len(user_message_times[message.author.id]) == SPAM_THRESHOLD:
        if current_time - user_message_times[message.author.id][0] < SPAM_TIMEFRAME:
            try:
                await message.author.ban(reason="Spamming")
                print(f"Banned {message.author} for spamming.")
                # Optionally, delete the spam messages
                await message.channel.purge(limit=SPAM_THRESHOLD, check=lambda m: m.author == message.author)
            except discord.Forbidden:
                print(f"Could not ban {message.author}. Missing permissions.")
            except discord.HTTPException as e:
                print(f"Failed to ban {message.author}: {e}")

@client.event
async def on_guild_role_create(role):
    """
    This function is called when a role is created.
    """
    guild = role.guild
    # --- Raid Detection & Banning ---
    await asyncio.sleep(2)
    entry = None
    async for e in guild.audit_logs(action=discord.AuditLogAction.role_create, limit=1):
        if e.target.id == role.id:
            entry = e
            break

    if entry and entry.user:
        user = entry.user
        current_time = time.time()

        user_actions[user.id]['role_create'] = [t for t in user_actions[user.id]['role_create'] if current_time - t < ACTION_TIMEFRAME]
        user_actions[user.id]['role_create'].append(current_time)

        if len(user_actions[user.id]['role_create']) >= ROLE_CREATE_THRESHOLD:
            print(f"Banning {user.name} for creating multiple roles.")
            try:
                await guild.ban(user, reason="Mass role creation.")
            except discord.Forbidden:
                print(f"Could not ban {user.name}. Missing permissions.")
            except discord.HTTPException as e:
                print(f"Failed to ban {user.name}: {e}")
            else:
                raid_reports[guild.id]['banned_users'] += 1

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

@client.event
async def on_guild_role_update(before, after):
    """
    This function is called when a role is updated, to keep the cache updated.
    """
    guild = after.guild
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

# --- Main Execution ---
if __name__ == "__main__":
    if not BOT_TOKEN:
        print("Error: The bot token is not set. Please create a .env file and set DISCORD_BOT_TOKEN.")
    else:
        client.run(BOT_TOKEN)
