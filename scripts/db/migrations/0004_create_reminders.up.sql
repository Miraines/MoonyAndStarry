CREATE TABLE reminders (
                           id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                           relationship_id UUID NOT NULL,
                           type VARCHAR(20) NOT NULL
                               CHECK (type IN ('anniversary','first_date','custom')),
                           date DATE NOT NULL,
                           text VARCHAR(255) NOT NULL,
                           frequency VARCHAR(10) NOT NULL
                               CHECK (frequency IN ('once','yearly','monthly')),
                           is_sent BOOLEAN NOT NULL DEFAULT FALSE,
                           created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                           CONSTRAINT fk_reminder_rel FOREIGN KEY (relationship_id)
                               REFERENCES relationships(id) ON DELETE CASCADE
);
