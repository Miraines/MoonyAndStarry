CREATE TABLE mood_entries (
                              id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                              relationship_id UUID NOT NULL,
                              user_id UUID NOT NULL,
                              mood VARCHAR(20) NOT NULL
                                  CHECK (mood IN ('happy','thoughtful','sad','angry','irritated')),
                              note TEXT,
                              created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                              CONSTRAINT fk_mood_rel FOREIGN KEY (relationship_id)
                                  REFERENCES relationships(id) ON DELETE CASCADE,
                              CONSTRAINT fk_mood_user FOREIGN KEY (user_id)
                                  REFERENCES users(id) ON DELETE CASCADE
);
