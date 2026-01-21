import os
import json
import time
import asyncio
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import discord
from discord.ext import commands, tasks

# =========================
#  CONFIG
# =========================
DEVELOPER_TAG = "rasiktop1_33126"
DATA_FILE = "antiraid_data.json"

# Anti-Join Flood
JOIN_WINDOW_SEC = 15
JOIN_THRESHOLD = 6
LOCKDOWN_MINUTES = 10

# Quarantine
QUARANTINE_ROLE_NAME = "Quarantine"

# Anti-spam (rate)
MSG_WINDOW_SEC = 6
MSG_THRESHOLD = 7
TIMEOUT_SECONDS = 60

# Anti-nuke window
NUKE_WINDOW_SEC = 20
CH_CREATE_THRESHOLD = 4
CH_DELETE_THRESHOLD = 3
ROLE_CREATE_THRESHOLD = 4
ROLE_DELETE_THRESHOLD = 3
BAN_THRESHOLD = 3
KICK_THRESHOLD = 3

# Punishment for nuke executor
NUKE_TIMEOUT_SECONDS = 3600  # 1 hour

# =========================
#  TOKEN (ENV ONLY)
# =========================
TOKEN = os.getenv("DISCORD_TOKEN")
if not TOKEN:
    raise RuntimeError("DISCORD_TOKEN не задан в переменных окружения!")

# =========================
#  INTENTS
# =========================
intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.messages = True
intents.message_content = True  # выключи, если не нужен анти-спам по сообщениям

bot = commands.Bot(command_prefix="!", intents=intents)

# =========================
#  STATE (runtime)
# =========================
join_times = defaultdict(lambda: deque(maxlen=600))                 # guild_id -> timestamps
lockdown_until = {}                                                # guild_id -> unix_ts
msg_times = defaultdict(lambda: deque(maxlen=250))                 # (guild_id, user_id) -> timestamps
nuke_times = defaultdict(lambda: deque(maxlen=400))                # (guild_id, executor_id, key) -> timestamps

# =========================
#  PERSISTED SETTINGS
# =========================
# settings[guild_id_str] = {
#   "log_channel_id": int|None,
#   "whitelist_users": [user_id],
#   "admin_users": [user_id],
#   "admin_roles": [role_id]
# }
settings = {}
settings_lock = asyncio.Lock()


def footer_text() -> str:
    return f"Разработчик: {DEVELOPER_TAG}"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def now_ts() -> float:
    return time.time()


def is_lockdown(guild_id: int) -> bool:
    return lockdown_until.get(guild_id, 0) > now_ts()


async def load_settings():
    global settings
    if not os.path.exists(DATA_FILE):
        settings = {}
        return
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            settings = json.load(f)
    except Exception:
        settings = {}


async def save_settings():
    async with settings_lock:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)


def get_cfg(guild_id: int) -> dict:
    gid = str(guild_id)
    if gid not in settings:
        settings[gid] = {
            "log_channel_id": None,
            "whitelist_users": [],
            "admin_users": [],
            "admin_roles": []
        }
    return settings[gid]


def is_whitelisted(guild_id: int, user_id: int) -> bool:
    cfg = get_cfg(guild_id)
    return user_id in cfg.get("whitelist_users", [])


def has_admin_system_rights(member: discord.Member) -> bool:
    """
    Наша система админов:
    - Discord админ (administrator) всегда проходит
    - admin_users
    - admin_roles
    """
    if member.guild_permissions.administrator:
        return True

    cfg = get_cfg(member.guild.id)
    if member.id in cfg.get("admin_users", []):
        return True

    admin_roles = set(cfg.get("admin_roles", []))
    if admin_roles:
        for r in member.roles:
            if r.id in admin_roles:
                return True

    return False


def requires_admin():
    async def predicate(ctx: commands.Context):
        if not ctx.guild or not isinstance(ctx.author, discord.Member):
            return False
        return has_admin_system_rights(ctx.author)
    return commands.check(predicate)


async def log_event(guild: discord.Guild, text: str):
    cfg = get_cfg(guild.id)
    ch_id = cfg.get("log_channel_id")
    if not ch_id:
        return
    ch = guild.get_channel(int(ch_id))
    if not ch:
        return
    try:
        embed = discord.Embed(description=text, timestamp=utcnow())
        embed.set_footer(text=footer_text())
        await ch.send(embed=embed)
    except Exception:
        pass


async def ensure_quarantine_role(guild: discord.Guild) -> discord.Role:
    role = discord.utils.get(guild.roles, name=QUARANTINE_ROLE_NAME)
    if role:
        return role
    return await guild.create_role(name=QUARANTINE_ROLE_NAME, reason="Anti-raid: create quarantine role")


async def quarantine_member(member: discord.Member, reason: str):
    role = await ensure_quarantine_role(member.guild)
    try:
        await member.add_roles(role, reason=reason)
    except Exception:
        pass


async def apply_lockdown(guild: discord.Guild, reason: str):
    lockdown_until[guild.id] = now_ts() + LOCKDOWN_MINUTES * 60
    everyone = guild.default_role

    for ch in guild.channels:
        try:
            ow = ch.overwrites_for(everyone)
            if isinstance(ch, (discord.TextChannel, discord.ForumChannel)):
                ow.send_messages = False
                ow.add_reactions = False
            elif isinstance(ch, discord.VoiceChannel):
                ow.connect = False
                ow.speak = False
            await ch.set_permissions(everyone, overwrite=ow, reason=reason)
        except Exception:
            pass

    await log_event(guild, f"🛡️ **LOCKDOWN ВКЛЮЧЁН** на {LOCKDOWN_MINUTES} мин.\nПричина: {reason}")


async def lift_lockdown(guild: discord.Guild):
    everyone = guild.default_role
    for ch in guild.channels:
        try:
            ow = ch.overwrites_for(everyone)
            changed = False

            if isinstance(ch, (discord.TextChannel, discord.ForumChannel)):
                if ow.send_messages is False:
                    ow.send_messages = None
                    changed = True
                if ow.add_reactions is False:
                    ow.add_reactions = None
                    changed = True

            elif isinstance(ch, discord.VoiceChannel):
                if ow.connect is False:
                    ow.connect = None
                    changed = True
                if ow.speak is False:
                    ow.speak = None
                    changed = True

            if changed:
                await ch.set_permissions(everyone, overwrite=ow, reason="Anti-raid: lift lockdown")
        except Exception:
            pass

    lockdown_until[guild.id] = 0
    await log_event(guild, "✅ **LOCKDOWN СНЯТ**")


async def get_recent_audit_executor(guild: discord.Guild, action: discord.AuditLogAction, target_id: int | None = None):
    """
    Требуется View Audit Log у бота.
    """
    try:
        async for entry in guild.audit_logs(limit=10, action=action):
            # только свежие
            if entry.created_at and (utcnow() - entry.created_at).total_seconds() > 20:
                continue
            if target_id is not None:
                if getattr(entry.target, "id", None) != target_id:
                    continue
            user = entry.user
            if not user:
                continue
            member = guild.get_member(user.id)
            return member, entry
    except Exception:
        pass
    return None, None


def bump_nuke(guild_id: int, executor_id: int, key: str) -> int:
    dq = nuke_times[(guild_id, executor_id, key)]
    t = now_ts()
    dq.append(t)
    while dq and (t - dq[0]) > NUKE_WINDOW_SEC:
        dq.popleft()
    return len(dq)


async def timeout_member(member: discord.Member, seconds: int, reason: str):
    until = utcnow() + timedelta(seconds=seconds)
    if hasattr(member, "timeout"):
        await member.timeout(until, reason=reason)
    else:
        await member.edit(timed_out_until=until, reason=reason)


async def punish_executor(guild: discord.Guild, executor: discord.Member, reason: str):
    if executor.bot:
        return
    if is_whitelisted(guild.id, executor.id):
        await log_event(guild, f"⚠️ Anti-nuke: **{executor}** в whitelist, наказание пропущено.\nПричина: {reason}")
        return
    if has_admin_system_rights(executor):
        await log_event(guild, f"⚠️ Anti-nuke: **{executor}** админ/роль админа, наказание пропущено.\nПричина: {reason}")
        return

    try:
        await timeout_member(executor, NUKE_TIMEOUT_SECONDS, reason=reason)
        await log_event(guild, f"⛔ **Anti-nuke наказание:** timeout {NUKE_TIMEOUT_SECONDS}s для **{executor}**\nПричина: {reason}")
    except Exception:
        await log_event(guild, f"❌ Не смог наказать **{executor}** (проверь права бота). Причина: {reason}")


def parse_duration(s: str) -> int:
    """
    10s, 5m, 2h, 3d -> seconds
    """
    s = s.strip().lower()
    if s.isdigit():
        return int(s)
    unit = s[-1]
    val = int(s[:-1])
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(unit)
    if not mult:
        raise ValueError("bad duration")
    return val * mult


# =========================
#  BACKGROUND WATCHER (FIXED)
# =========================
@tasks.loop(seconds=10)
async def lockdown_watcher():
    for g in bot.guilds:
        if g.id in lockdown_until and lockdown_until[g.id] and not is_lockdown(g.id):
            await lift_lockdown(g)

@lockdown_watcher.before_loop
async def before_lockdown_watcher():
    await bot.wait_until_ready()


# =========================
#  EVENTS
# =========================
@bot.event
async def on_ready():
    await load_settings()
    print(f"Logged in as {bot.user} ({bot.user.id})")
    if not lockdown_watcher.is_running():
        lockdown_watcher.start()


@bot.event
async def on_member_join(member: discord.Member):
    g = member.guild
    t = now_ts()
    dq = join_times[g.id]
    dq.append(t)
    while dq and (t - dq[0]) > JOIN_WINDOW_SEC:
        dq.popleft()

    if is_lockdown(g.id):
        await quarantine_member(member, "Anti-raid: joined during lockdown")
        await log_event(g, f"🧷 Карантин новичка (локдаун): **{member}**")
        return

    if len(dq) >= JOIN_THRESHOLD:
        await apply_lockdown(g, reason=f"{len(dq)} joins / {JOIN_WINDOW_SEC}s")
        await quarantine_member(member, "Anti-raid: raid detected")
        await log_event(g, f"🚨 Join-flood: включил локдаун. Последний вошедший: **{member}**")


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return

    member = message.author if isinstance(message.author, discord.Member) else None
    if member and (is_whitelisted(message.guild.id, member.id) or has_admin_system_rights(member)):
        await bot.process_commands(message)
        return

    key = (message.guild.id, message.author.id)
    dq = msg_times[key]
    t = now_ts()
    dq.append(t)
    while dq and (t - dq[0]) > MSG_WINDOW_SEC:
        dq.popleft()

    if member and len(dq) >= MSG_THRESHOLD:
        try:
            await timeout_member(member, TIMEOUT_SECONDS, reason="Anti-spam: rate limit")
            await log_event(message.guild, f"💬 Anti-spam: timeout {TIMEOUT_SECONDS}s для **{member}**")
        except Exception:
            pass
        dq.clear()

    await bot.process_commands(message)


# =========================
#  ANTI-NUKE EVENTS
# =========================
@bot.event
async def on_guild_channel_create(channel: discord.abc.GuildChannel):
    g = channel.guild
    executor, _ = await get_recent_audit_executor(g, discord.AuditLogAction.channel_create, target_id=channel.id)
    if not executor:
        return

    c = bump_nuke(g.id, executor.id, "ch_create")
    if c >= CH_CREATE_THRESHOLD and not is_lockdown(g.id):
        await apply_lockdown(g, reason=f"Anti-nuke: channel_create by {executor} ({c}/{NUKE_WINDOW_SEC}s)")
        await punish_executor(g, executor, reason="Anti-nuke: массовое создание каналов")


@bot.event
async def on_guild_channel_delete(channel: discord.abc.GuildChannel):
    g = channel.guild
    executor, _ = await get_recent_audit_executor(g, discord.AuditLogAction.channel_delete)
    if not executor:
        return

    c = bump_nuke(g.id, executor.id, "ch_delete")
    if c >= CH_DELETE_THRESHOLD and not is_lockdown(g.id):
        await apply_lockdown(g, reason=f"Anti-nuke: channel_delete by {executor} ({c}/{NUKE_WINDOW_SEC}s)")
        await punish_executor(g, executor, reason="Anti-nuke: массовое удаление каналов")


@bot.event
async def on_guild_role_create(role: discord.Role):
    g = role.guild
    executor, _ = await get_recent_audit_executor(g, discord.AuditLogAction.role_create, target_id=role.id)
    if not executor:
        return

    c = bump_nuke(g.id, executor.id, "role_create")
    if c >= ROLE_CREATE_THRESHOLD and not is_lockdown(g.id):
        await apply_lockdown(g, reason=f"Anti-nuke: role_create by {executor} ({c}/{NUKE_WINDOW_SEC}s)")
        await punish_executor(g, executor, reason="Anti-nuke: массовое создание ролей")


@bot.event
async def on_guild_role_delete(role: discord.Role):
    g = role.guild
    executor, _ = await get_recent_audit_executor(g, discord.AuditLogAction.role_delete)
    if not executor:
        return

    c = bump_nuke(g.id, executor.id, "role_delete")
    if c >= ROLE_DELETE_THRESHOLD and not is_lockdown(g.id):
        await apply_lockdown(g, reason=f"Anti-nuke: role_delete by {executor} ({c}/{NUKE_WINDOW_SEC}s)")
        await punish_executor(g, executor, reason="Anti-nuke: массовое удаление ролей")


@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User):
    executor, _ = await get_recent_audit_executor(guild, discord.AuditLogAction.ban, target_id=user.id)
    if not executor:
        return

    c = bump_nuke(guild.id, executor.id, "ban")
    if c >= BAN_THRESHOLD and not is_lockdown(guild.id):
        await apply_lockdown(guild, reason=f"Anti-nuke: bans by {executor} ({c}/{NUKE_WINDOW_SEC}s)")
        await punish_executor(guild, executor, reason="Anti-nuke: массовые баны")


@bot.event
async def on_member_remove(member: discord.Member):
    g = member.guild
    executor, _ = await get_recent_audit_executor(g, discord.AuditLogAction.kick, target_id=member.id)
    if not executor:
        return

    c = bump_nuke(g.id, executor.id, "kick")
    if c >= KICK_THRESHOLD and not is_lockdown(g.id):
        await apply_lockdown(g, reason=f"Anti-nuke: kicks by {executor} ({c}/{NUKE_WINDOW_SEC}s)")
        await punish_executor(g, executor, reason="Anti-nuke: массовые кики")


# =========================
#  COMMANDS: HELP
# =========================
@bot.command(name="helpme")
async def helpme(ctx: commands.Context):
    txt = (
        "**Anti-raid / Anti-nuke / Moderation**\n"
        "`!setlog #канал` — куда писать логи\n"
        "`!wladd @user` / `!wldel @user` — whitelist (не наказывать)\n"
        "`!adminadd @user` / `!admindel @user` — админ в системе бота\n"
        "`!adminroleadd @role` / `!adminroledel @role` — админ-роль\n"
        "\n"
        "**Управление защитой**\n"
        "`!lockdown [мин] [причина]` / `!unlock` / `!status`\n"
        "\n"
        "**Модерация**\n"
        "`!purge [N]`\n"
        "`!timeout @user 10m [причина]` / `!untimeout @user`\n"
        "`!kick @user [причина]` / `!ban @user [причина]` / `!unban user_id`\n"
    )
    embed = discord.Embed(description=txt)
    embed.set_footer(text=footer_text())
    await ctx.reply(embed=embed)


# =========================
#  COMMANDS: ADMIN SYSTEM
# =========================
@bot.command(name="setlog")
@requires_admin()
async def setlog(ctx: commands.Context, channel: discord.TextChannel | None = None):
    channel = channel or ctx.channel
    cfg = get_cfg(ctx.guild.id)
    cfg["log_channel_id"] = channel.id
    await save_settings()

    embed = discord.Embed(description=f"✅ Лог-канал установлен: {channel.mention}")
    embed.set_footer(text=footer_text())
    await ctx.reply(embed=embed)


@bot.command(name="wladd")
@requires_admin()
async def wladd(ctx: commands.Context, member: discord.Member):
    cfg = get_cfg(ctx.guild.id)
    wl = set(cfg.get("whitelist_users", []))
    wl.add(member.id)
    cfg["whitelist_users"] = list(wl)
    await save_settings()

    embed = discord.Embed(description=f"✅ Добавил в whitelist: **{member}**")
    embed.set_footer(text=footer_text())
    await ctx.reply(embed=embed)


@bot.command(name="wldel")
@requires_admin()
async def wldel(ctx: commands.Context, member: discord.Member):
    cfg = get_cfg(ctx.guild.id)
    wl = set(cfg.get("whitelist_users", []))
    wl.discard(member.id)
    cfg["whitelist_users"] = list(wl)
    await save_settings()

    embed = discord.Embed(description=f"✅ Удалил из whitelist: **{member}**")
    embed.set_footer(text=footer_text())
    await ctx.reply(embed=embed)


@bot.command(name="adminadd")
@requires_admin()
async def adminadd(ctx: commands.Context, member: discord.Member):
    cfg = get_cfg(ctx.guild.id)
    au = set(cfg.get("admin_users", []))
    au.add(member.id)
    cfg["admin_users"] = list(au)
    await save_settings()

    embed = discord.Embed(description=f"✅ Добавил админа (система бота): **{member}**")
    embed.set_footer(text=footer_text())
    await ctx.reply(embed=embed)


@bot.command(name="admindel")
@requires_admin()
async def admindel(ctx: commands.Context, member: discord.Member):
    cfg = get_cfg(ctx.guild.id)
    au = set(cfg.get("admin_users", []))
    au.discard(member.id)
    cfg["admin_users"] = list(au)
    await save_settings()

    embed = discord.Embed(description=f"✅ Удалил админа (система бота): **{member}**")
    embed.set_footer(text=footer_text())
    await ctx.reply(embed=embed)


@bot.command(name="adminroleadd")
@requires_admin()
async def adminroleadd(ctx: commands.Context, role: discord.Role):
    cfg = get_cfg(ctx.guild.id)
    ar = set(cfg.get("admin_roles", []))
    ar.add(role.id)
    cfg["admin_roles"] = list(ar)
    await save_settings()

    embed = discord.Embed(description=f"✅ Добавил админ-роль: **{role.name}**")
    embed.set_footer(text=footer_text())
    await ctx.reply(embed=embed)


@bot.command(name="adminroledel")
@requires_admin()
async def adminroledel(ctx: commands.Context, role: discord.Role):
    cfg = get_cfg(ctx.guild.id)
    ar = set(cfg.get("admin_roles", []))
    ar.discard(role.id)
    cfg["admin_roles"] = list(ar)
    await save_settings()

    embed = discord.Embed(description=f"✅ Удалил админ-роль: **{role.name}**")
    embed.set_footer(text=footer_text())
    await ctx.reply(embed=embed)


# =========================
#  COMMANDS: SECURITY CONTROL
# =========================
@bot.command(name="lockdown")
@requires_admin()
async def cmd_lockdown(ctx: commands.Context, minutes: int = LOCKDOWN_MINUTES, *, reason: str = "Manual lockdown"):
    minutes = max(1, min(minutes, 180))
    global LOCKDOWN_MINUTES
    old = LOCKDOWN_MINUTES
    LOCKDOWN_MINUTES = minutes
    await apply_lockdown(ctx.guild, reason=f"{reason} (by {ctx.author})")
    LOCKDOWN_MINUTES = old

    embed = discord.Embed(description=f"🛡️ Lockdown включён на **{minutes} мин.**\nПричина: {reason}")
    embed.set_footer(text=footer_text())
    await ctx.reply(embed=embed)


@bot.command(name="unlock")
@requires_admin()
async def cmd_unlock(ctx: commands.Context):
    await lift_lockdown(ctx.guild)
    embed = discord.Embed(description="✅ Lockdown снят.")
    embed.set_footer(text=footer_text())
    await ctx.reply(embed=embed)


@bot.command(name="status")
@requires_admin()
async def cmd_status(ctx: commands.Context):
    if is_lockdown(ctx.guild.id):
        left = int(lockdown_until.get(ctx.guild.id, 0) - now_ts())
        embed = discord.Embed(description=f"🛡️ Lockdown активен, осталось ~**{left}s**.")
    else:
        embed = discord.Embed(description="🟢 Lockdown не активен.")
    embed.set_footer(text=footer_text())
    await ctx.reply(embed=embed)


# =========================
#  COMMANDS: MODERATION
# =========================
@bot.command(name="purge")
@requires_admin()
@commands.has_permissions(manage_messages=True)
async def purge(ctx: commands.Context, amount: int = 20):
    amount = max(1, min(amount, 200))
    deleted = await ctx.channel.purge(limit=amount + 1)
    embed = discord.Embed(description=f"🧹 Удалено сообщений: **{len(deleted) - 1}**")
    embed.set_footer(text=footer_text())
    await ctx.send(embed=embed, delete_after=5)


@bot.command(name="timeout")
@requires_admin()
@commands.has_permissions(moderate_members=True)
async def cmd_timeout(ctx: commands.Context, member: discord.Member, duration: str, *, reason: str = "No reason"):
    if is_whitelisted(ctx.guild.id, member.id) or has_admin_system_rights(member):
        return await ctx.reply("⚠️ Этот пользователь whitelist/админ в системе бота — таймаут не выдаю.")

    secs = parse_duration(duration)
    secs = max(5, min(secs, 28 * 86400))
    try:
        await timeout_member(member, secs, reason=reason)
        await log_event(ctx.guild, f"⏱️ Timeout: **{member}** на {secs}s. Причина: {reason}")
        embed = discord.Embed(description=f"⏱️ Таймаут для **{member}** на **{secs}s**\nПричина: {reason}")
        embed.set_footer(text=footer_text())
        await ctx.reply(embed=embed)
    except Exception:
        await ctx.reply("❌ Не смог выдать таймаут. Проверь права бота и иерархию ролей.")


@bot.command(name="untimeout")
@requires_admin()
@commands.has_permissions(moderate_members=True)
async def cmd_untimeout(ctx: commands.Context, member: discord.Member, *, reason: str = "No reason"):
    try:
        if hasattr(member, "timeout"):
            await member.timeout(None, reason=reason)
        else:
            await member.edit(timed_out_until=None, reason=reason)
        await log_event(ctx.guild, f"✅ Timeout снят: **{member}**. Причина: {reason}")
        embed = discord.Embed(description=f"✅ Таймаут снят для **{member}**\nПричина: {reason}")
        embed.set_footer(text=footer_text())
        await ctx.reply(embed=embed)
    except Exception:
        await ctx.reply("❌ Не смог снять таймаут. Проверь права бота.")


@bot.command(name="kick")
@requires_admin()
@commands.has_permissions(kick_members=True)
async def cmd_kick(ctx: commands.Context, member: discord.Member, *, reason: str = "No reason"):
    if is_whitelisted(ctx.guild.id, member.id) or has_admin_system_rights(member):
        return await ctx.reply("⚠️ Этот пользователь whitelist/админ в системе бота — кик не делаю.")
    try:
        await member.kick(reason=reason)
        await log_event(ctx.guild, f"👢 Kick: **{member}**. Причина: {reason}")
        embed = discord.Embed(description=f"👢 Кикнул **{member}**\nПричина: {reason}")
        embed.set_footer(text=footer_text())
        await ctx.reply(embed=embed)
    except Exception:
        await ctx.reply("❌ Не смог кикнуть. Проверь права и иерархию ролей.")


@bot.command(name="ban")
@requires_admin()
@commands.has_permissions(ban_members=True)
async def cmd_ban(ctx: commands.Context, member: discord.Member, *, reason: str = "No reason"):
    if is_whitelisted(ctx.guild.id, member.id) or has_admin_system_rights(member):
        return await ctx.reply("⚠️ Этот пользователь whitelist/админ в системе бота — бан не делаю.")
    try:
        await member.ban(reason=reason, delete_message_days=0)
        await log_event(ctx.guild, f"🔨 Ban: **{member}**. Причина: {reason}")
        embed = discord.Embed(description=f"🔨 Забанил **{member}**\nПричина: {reason}")
        embed.set_footer(text=footer_text())
        await ctx.reply(embed=embed)
    except Exception:
        await ctx.reply("❌ Не смог забанить. Проверь права и иерархию ролей.")


@bot.command(name="unban")
@requires_admin()
@commands.has_permissions(ban_members=True)
async def cmd_unban(ctx: commands.Context, user_id: int, *, reason: str = "No reason"):
    try:
        user = await bot.fetch_user(user_id)
        await ctx.guild.unban(user, reason=reason)
        await log_event(ctx.guild, f"✅ Unban: **{user}**. Причина: {reason}")
        embed = discord.Embed(description=f"✅ Разбанил **{user}**\nПричина: {reason}")
        embed.set_footer(text=footer_text())
        await ctx.reply(embed=embed)
    except Exception:
        await ctx.reply("❌ Не смог разбанить. Убедись, что ID верный и пользователь в бан-листе.")


# =========================
#  RUN
# =========================
bot.run(TOKEN)
