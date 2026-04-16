# Frontend build
cd application

# Database migrations
./bin/console doctrine:migrations:migrate --no-interaction

# Serving assets in prod
./bin/console asset-map:compile

# Serving assets in prod
./bin/console aropixel:storage:seed
