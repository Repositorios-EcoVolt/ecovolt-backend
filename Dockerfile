# Use base image
FROM node:20.12.2

# Create a directory in the container to store the app
RUN mkdir /app

# Set the working directory
WORKDIR /app

# Copy bin to the container
COPY bin /app/bin

# Copy controllers to the container
COPY controllers /app/controllers

# Copy the models to the container
COPY models /app/models

# Copy the routes to the container
COPY routes /app/routes

# Copy the public folder to the container (static files)
COPY public /app/public

# Copy database.js to the container
COPY database.js .

# Copy the app.js file to the container
COPY app.js .

# Copy the package.json file to the container
COPY package.json .

# Copy .env file to the container
COPY .env .

# Install the dependencies
RUN npm install

# Expose the port
EXPOSE 8000

# Start the application
CMD ["npm", "start"]
