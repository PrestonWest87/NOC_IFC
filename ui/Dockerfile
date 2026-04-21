# Use Node 18 Alpine (Lightweight and perfectly compatible with Vite 5)
FROM node:18-alpine

WORKDIR /app

# Copy dependency files first to leverage Docker layer caching
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm install

# Copy the rest of your React source code
COPY . .

# Expose the default Vite port
EXPOSE 5173

# Start the Vite development server
CMD ["npm", "run", "dev"]
