CREATE TABLE photos (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        relationship_id UUID NOT NULL,
                        url VARCHAR(500) NOT NULL,
                        thumbnail_url VARCHAR(500),
                        caption VARCHAR(255),
                        uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                        CONSTRAINT fk_photo_rel FOREIGN KEY (relationship_id)
                            REFERENCES relationships(id) ON DELETE CASCADE
);
