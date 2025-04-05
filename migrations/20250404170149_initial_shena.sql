-------------------------------------
-- 用户表（无邮箱验证字段精简版）
-------------------------------------
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(10) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    avatar_url TEXT,
    bio TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-------------------------------------
-- 聊天室/群组表
-------------------------------------
CREATE TABLE rooms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(128) NOT NULL,
    owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
    is_public BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-------------------------------------
-- 房间成员关系表
-------------------------------------
CREATE TABLE room_members (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    room_id UUID REFERENCES rooms(id) ON DELETE CASCADE,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, room_id)
);

-------------------------------------
-- 消息表（支持群聊/私聊）
-------------------------------------
CREATE TABLE messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    msg_type VARCHAR(10) NOT NULL CHECK (
        msg_type IN ('group', 'private')
    ),
    
    -- 群聊相关字段
    room_id UUID REFERENCES rooms(id) ON DELETE CASCADE,
    
    -- 私聊相关字段
    conversation_hash VARCHAR(64),
    recipient_id UUID REFERENCES users(id) ON DELETE CASCADE,
    
    -- 公共字段
    sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- 校验约束
    CHECK (
        (msg_type = 'group' AND room_id IS NOT NULL) OR
        (msg_type = 'private' AND recipient_id IS NOT NULL)
    )
);

-------------------------------------
-- 触发器函数
-------------------------------------
-- 自动更新时间戳
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 自动生成私聊会话哈希
CREATE OR REPLACE FUNCTION gen_conversation_hash()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.msg_type = 'private' THEN
        NEW.conversation_hash := MD5(
            LEAST(NEW.sender_id::TEXT, NEW.recipient_id::TEXT) || 
            GREATEST(NEW.sender_id::TEXT, NEW.recipient_id::TEXT)
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-------------------------------------
-- 触发器
-------------------------------------
-- 用户表更新时间
CREATE TRIGGER trg_update_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- 房间表更新时间
CREATE TRIGGER trg_update_rooms_updated_at
BEFORE UPDATE ON rooms
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- 消息会话哈希生成
CREATE TRIGGER trg_set_conversation_hash
BEFORE INSERT ON messages
FOR EACH ROW
EXECUTE FUNCTION gen_conversation_hash();

-------------------------------------
-- 索引优化
-------------------------------------
-- 用户表
CREATE INDEX idx_users_email ON users(email);

-- 房间表
CREATE INDEX idx_rooms_owner ON rooms(owner_id);

-- 消息表
CREATE INDEX idx_messages_room ON messages(room_id, created_at);
CREATE INDEX idx_messages_sender ON messages(sender_id, created_at);
CREATE INDEX idx_messages_conversation ON messages(conversation_hash, created_at);
CREATE INDEX idx_messages_recipient ON messages(recipient_id, created_at);