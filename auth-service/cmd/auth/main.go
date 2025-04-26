package main

import (
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/config"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
)

func main() {

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Не удалось загрузить конфиг: %v", err)
	}

	sourceURL := "file://scripts/db/migrations"
	m, err := migrate.New(sourceURL, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Не удалось создать инстанс мигратора: %v", err)
	}

	version, dirty, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		log.Fatalf("Не удалось получить версию БД: %v", err)
	}
	if dirty {
		prev := int(version) - 1
		if prev < 0 {
			prev = 0
		}
		log.Printf("База в dirty‑состоянии (версия %d), откатываю к версии %d", version, prev)
		if err := m.Force(int(uint(prev))); err != nil {
			log.Fatalf("Не удалось принудительно сбросить версию на %d: %v", prev, err)
		}
		log.Printf("Успешно откатились к версии %d", prev)
	}

	if err := m.Up(); err != nil {
		if err == migrate.ErrNoChange {
			log.Println("Миграции не найдены — база актуальна")
		} else {
			// при ошибке снова проверяем dirty и пытаемся вернуть на предыдущую версию
			v2, dirty2, verr := m.Version()
			if verr == nil && dirty2 {
				prev2 := int(v2) - 1
				if prev2 < 0 {
					prev2 = 0
				}
				log.Printf("Ошибка миграции на версии %d: %v", v2, err)
				log.Printf("Откатываемся к версии %d", prev2)
				if ferr := m.Force(int(uint(prev2))); ferr != nil {
					log.Fatalf("Не удалось принудительно сбросить версию на %d: %v", prev2, ferr)
				}
				log.Printf("Успешно откатились к версии %d после сбоя", prev2)
			}
			log.Fatalf("Не удалось применить миграции: %v", err)
		}
	}
	log.Println("Миграции успешно применены")

	db, err := gorm.Open(postgres.Open(cfg.DatabaseURL), &gorm.Config{})
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}

	log.Println("Приложение запущено, готово принимать запросы...")

	sqlDB, err := db.DB()

	if err != nil {
		log.Fatalf("Не удалось получить экземпляр базы данных: %v", err)
	}

	if err := sqlDB.Ping(); err != nil {
		log.Fatalf("Не удалось пинговать базу: %v", err)
	}

	defer sqlDB.Close()

	log.Println("Подключение к базе проверено успешно")
	log.Println("Приложение запущено, готово принимать запросы...")
}
