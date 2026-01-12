import discord

async def create_channel(guild, channel_name, is_voice=False, category=None):
    """Creates a new channel in the guild."""
    if is_voice:
        return await guild.create_voice_channel(name=channel_name, category=category)
    else:
        return await guild.create_text_channel(name=channel_name, category=category)

async def delete_channel(channel):
    """Deletes a channel."""
    await channel.delete()

async def create_role(guild, role_name, color=discord.Color.default(), hoist=False):
    """Creates a new role in the guild."""
    return await guild.create_role(name=role_name, color=color, hoist=hoist)

async def assign_role(member, role):
    """Assigns a role to a member."""
    await member.add_roles(role)

async def remove_role(member, role):
    """Removes a role from a member."""
    await member.remove_roles(role)

async def ban_member(member, reason=""):
    """Bans a member from the guild."""
    await member.ban(reason=reason)

async def kick_member(member, reason=""):
    """Kicks a member from the guild."""
    await member.kick(reason=reason)

async def timeout_member(member, duration_seconds, reason=""):
    """Timeouts a member for a specified duration."""
    await member.timeout(discord.utils.utcnow() + discord.timedelta(seconds=duration_seconds), reason=reason)
