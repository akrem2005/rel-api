-- schema.sql - Full Database Schema (Run this completely)

-- CREATE DATABASE IF NOT EXISTS realestate;
-- USE realestate;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  role ENUM('user', 'agent', 'hotel', 'admin') DEFAULT 'user',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE properties (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  location VARCHAR(255) NOT NULL,
  price DECIMAL(12,2) NOT NULL,
  description TEXT,
  category ENUM('Apartment', 'House', 'Hotel', 'Villa', 'Office') NOT NULL,
  listingType ENUM('Rent', 'Sale', 'Hotel Booking') NOT NULL,
  bedrooms INT,
  bathrooms INT,
  area DECIMAL(10,2),
  images JSON,
  furnishingStatus VARCHAR(100),
  floorNumber INT,
  parkingSpaces INT,
  maxGuests INT,
  roomQuota INT DEFAULT 0,
  ownerId INT NOT NULL,
  isVerified BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (ownerId) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE bookings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  propertyId INT NOT NULL,
  userId INT NOT NULL,
  checkInDate DATE NOT NULL,
  checkOutDate DATE NOT NULL,
  guestsCount INT NOT NULL,
  paymentMethod ENUM('Credit Card', 'PayPal', 'Pay at Hotel'),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (propertyId) REFERENCES properties(id),
  FOREIGN KEY (userId) REFERENCES users(id)
);

CREATE TABLE favorites (
  id INT AUTO_INCREMENT PRIMARY KEY,
  userId INT NOT NULL,
  propertyId INT NOT NULL,
  UNIQUE KEY unique_fav (userId, propertyId),
  FOREIGN KEY (userId) REFERENCES users(id),
  FOREIGN KEY (propertyId) REFERENCES properties(id)
);

CREATE TABLE notifications (
  id INT AUTO_INCREMENT PRIMARY KEY,
  userId INT NOT NULL,
  message TEXT NOT NULL,
  isRead BOOLEAN DEFAULT FALSE,
  createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (userId) REFERENCES users(id)
);

CREATE TABLE applications (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  role ENUM('agent', 'hotel') NOT NULL,
  status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Subscription System
CREATE TABLE subscription_plans (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  role ENUM('agent', 'hotel') NOT NULL,
  price_per_month DECIMAL(10,2) DEFAULT 0.00,
  revenue_share_percent DECIMAL(5,2) DEFAULT 0.00,
  listing_credits INT DEFAULT 0,
  free_months INT DEFAULT 0,
  description TEXT,
  is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE user_subscriptions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  userId INT NOT NULL,
  planId INT NOT NULL,
  start_date DATE NOT NULL,
  end_date DATE NULL,
  credits_remaining INT DEFAULT 0,
  is_active BOOLEAN DEFAULT TRUE,
  payment_status ENUM('paid', 'pending', 'free_trial') DEFAULT 'free_trial',
  FOREIGN KEY (userId) REFERENCES users(id),
  FOREIGN KEY (planId) REFERENCES subscription_plans(id),
  UNIQUE KEY unique_active_sub (userId, is_active)
);

CREATE TABLE booking_commissions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  bookingId INT NOT NULL,
  hotelId INT NOT NULL,
  commission_amount DECIMAL(10,2) NOT NULL,
  percentage DECIMAL(5,2) NOT NULL,
  status ENUM('pending', 'paid') DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (bookingId) REFERENCES bookings(id),
  FOREIGN KEY (hotelId) REFERENCES users(id)
);