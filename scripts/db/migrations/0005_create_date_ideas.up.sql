CREATE TABLE date_ideas (
                            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                            category VARCHAR(10) NOT NULL
                                CHECK (category IN ('activity','movie','music')),
                            title VARCHAR(255) NOT NULL,
                            description TEXT,
                            created_by VARCHAR(10) NOT NULL
                                CHECK (created_by IN ('system','user')),
                            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
