CREATE TABLE relationships (
                               id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                               user_a_id    uuid NOT NULL,
                               user_b_id    uuid NOT NULL,
                               pairing_code varchar(6) NOT NULL UNIQUE,
                               since_date   date NOT NULL,
                               status       varchar(10) NOT NULL
                                   CHECK (status IN ('pending','active','blocked')),
                               created_at   timestamptz NOT NULL DEFAULT now(),
                               updated_at   timestamptz NOT NULL DEFAULT now(),
                               CONSTRAINT fk_rel_user_a FOREIGN KEY (user_a_id) REFERENCES users(id),
                               CONSTRAINT fk_rel_user_b FOREIGN KEY (user_b_id) REFERENCES users(id)
);

-- одно‑значный «неупорядоченный» индекс
CREATE UNIQUE INDEX one_pair_idx
    ON relationships (LEAST(user_a_id, user_b_id),
                      GREATEST(user_a_id, user_b_id));
