# Simple PHP + Apache image
FROM php:8.2-apache

# Copy app into web root
COPY . /var/www/html/

# Permissions
RUN chown -R www-data:www-data /var/www/html

# Optional: enable .htaccess later if you need
# RUN a2enmod rewrite

# Start Apache (listens on port 80)
CMD ["apache2-foreground"]
