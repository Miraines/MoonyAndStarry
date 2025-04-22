CREATE TABLE idea_usages (
                             id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                             relationship_id UUID NOT NULL,
                             idea_id UUID NOT NULL,
                             used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                             CONSTRAINT fk_usage_rel FOREIGN KEY (relationship_id)
                                 REFERENCES relationships(id) ON DELETE CASCADE,
                             CONSTRAINT fk_usage_idea FOREIGN KEY (idea_id)
                                 REFERENCES date_ideas(id) ON DELETE CASCADE
);
