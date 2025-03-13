# Start the development environment
start-dev: 
  docker-compose up -d
  pnpm start:dev

# Stop the development environment
stop-dev:
  docker-compose down
  
# Start prisma studio
prisma-studio:
  pnpm dlx prisma studio
