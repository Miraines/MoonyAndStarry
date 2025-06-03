package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/model"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestPostgresUserRepo_CRUD(t *testing.T) {
	repo := NewPostgresUserRepo(setupDB(t))
	ctx := context.Background()
	user := model.User{ID: uuid.New(), Email: "e@e", Username: "u", PasswordHash: "h", CreatedAt: time.Now()}
	id, err := repo.CreateUser(ctx, user)
	if err != nil || id != user.ID {
		t.Fatalf("create %v", err)
	}
	got, err := repo.GetUserByEmail(ctx, user.Email)
	if err != nil || got.ID != user.ID {
		t.Fatalf("get by email %v", err)
	}
	got2, err := repo.GetUserByID(ctx, user.ID)
	if err != nil || got2.Email != user.Email {
		t.Fatalf("get by id %v", err)
	}
	if err := repo.UpdateUser(ctx, user); err != nil {
		t.Fatalf("update %v", err)
	}
	if err := repo.DeleteUser(ctx, user.ID); err != nil {
		t.Fatalf("delete %v", err)
	}
	if _, err := repo.GetUserByID(ctx, user.ID); !errors.IsNotFound(err) {
		t.Fatalf("expected not found")
	}
}
