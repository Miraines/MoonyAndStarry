CREATE TABLE notifications (
                               id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                               user_id UUID NOT NULL,
                               type VARCHAR(50) NOT NULL,
                               payload JSONB NOT NULL,
                               status VARCHAR(10) NOT NULL
                                   CHECK (status IN ('pending','sent','failed')),
                               scheduled_at TIMESTAMPTZ NOT NULL,
                               sent_at TIMESTAMPTZ,
                               CONSTRAINT fk_notif_user FOREIGN KEY (user_id)
                                   REFERENCES users(id) ON DELETE CASCADE
);
