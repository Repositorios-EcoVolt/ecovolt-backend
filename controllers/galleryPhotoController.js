const asyncHandler = require('express-async-handler');
const fs = require('fs');
const jwt = require('jsonwebtoken');

const GalleryPhotoSchema = require('../models/galleryPhoto');
const BlacklistedTokenSchema = require('../models/backlistedToken');


exports.get_gallery_photos = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    try {
        // Get all gallery photos
        const galleryPhotos = await GalleryPhotoSchema.find();

        // Get JWT token (bearer) from authorization header
        const header = req.headers['authorization'];
        let token = null;

        // Extract token from header or cookie
        if (typeof header !== 'undefined') {
            // Extract token from header
            const bearer = header.split(' ');
            token = bearer[1];
        } else {
            // Extract token from cookie
            if(req.cookies['JWT_token']){
                token = req.cookies['JWT_token'];
            } else {
                console.log('No token provided');
                const galleryPhotosDTO = galleryPhotos.map((galleryPhoto) => {
                    return {
                        id: galleryPhoto._id,
                        name: galleryPhoto.name,
                        picture: galleryPhoto.picture,
                        description: galleryPhoto.description
                    }

                }).filter((galleryPhoto) => galleryPhoto.active !== false);

                return res.status(200).send(galleryPhotosDTO);
            }
        }

        req.token = token;

        // Check if the token is blacklisted
        const blacklistedToken = await BlacklistedTokenSchema.findOne({ token: token });

        // JWT token is blacklisted
        if (blacklistedToken) {
            const galleryPhotosDTO = galleryPhotos.map((galleryPhoto) => {
                return {
                    id: galleryPhoto._id,
                    name: galleryPhoto.name,
                    picture: galleryPhoto.picture,
                    description: galleryPhoto.description
                }

            }).filter((galleryPhoto) => galleryPhoto.active !== false);

            return res.status(200).send(galleryPhotosDTO);
        }

        // Check if the token is valid
        jwt.verify(req.token, process.env.JWT_SECRET, async (err, authorizedData) => {
            if (err) {
                // --------------------------------------------------
                // Handle when JWT token is expired or invalid 
                // --------------------------------------------------

                // Decode JWT token
                const decodedJWT = jwt.decode(req.token, { complete: true });

                // If JWT is expired refresh token if it expired by 5 minutes (max 5 minutes of inactivity)
                if (err && !(err.name === 'TokenExpiredError' && decodedJWT.payload.exp + 300 >= (Date.now()/1000))) {
                    // Blacklist previous token
                    const blacklistedToken = new BlacklistedTokenSchema({
                        token: req.token,
                        expire_at: new Date().setTime((decodedJWT.payload.exp * 1000) + 300000)
                    });

                    // Save blacklisted token in database
                    await blacklistedToken.save();

                    // Refresh JWT token
                    const userDTO = decodedJWT.payload.userDTO;
                    const newToken = jwt.sign({ userDTO }, process.env.JWT_SECRET, { expiresIn: 300 });

                    // Erase previous token
                    res.clearCookie('JWT_token');

                    // Set token in 'JWT_token' cookie
                    res.cookie('JWT_token', newToken, { httpOnly: true, secure: true });

                    // Build DTO for authenticated users
                    const galleryPhotosDTO = galleryPhotos.map((galleryPhoto) => {
                        return {
                            id: galleryPhoto._id,
                            name: galleryPhoto.name,
                            picture: galleryPhoto.picture,
                            description: galleryPhoto.description,
                            uploaded_at: galleryPhoto.uploaded_at,
                            uploaded_by: galleryPhoto.uploaded_by,
                            updated_at: galleryPhoto.updated_at,
                            updated_by: galleryPhoto.updated_by,
                            active: galleryPhoto.active
                        }
                    });

                    // Send all gallery photos for authenticated users
                    return res.status(200).send(galleryPhotosDTO);
                }

                // JWT token is invalid or has expired more than 5 minutes
                const galleryPhotosDTO = galleryPhotos.map((galleryPhoto) => {
                    return {
                        id: galleryPhoto._id,
                        name: galleryPhoto.name,
                        picture: galleryPhoto.picture,
                        description: galleryPhoto.description
                    }

                }).filter((galleryPhoto) => galleryPhoto.active !== false);

                // Send all gallery photos for unauthenticated users
                return res.status(200).send(galleryPhotosDTO);
                
            } else {
                // Get gallery photos for authenticated users
                const galleryPhotosDTO = galleryPhotos.map((galleryPhoto) => {
                    return {
                        id: galleryPhoto._id,
                        name: galleryPhoto.name,
                        picture: galleryPhoto.picture,
                        description: galleryPhoto.description,
                        uploaded_at: galleryPhoto.uploaded_at,
                        uploaded_by: galleryPhoto.uploaded_by,
                        updated_at: galleryPhoto.updated_at,
                        updated_by: galleryPhoto.updated_by,
                        active: galleryPhoto.active
                    }
                });

                // Send all gallery photos for authenticated users
                return res.status(200).send(galleryPhotosDTO);
            }
        });

    } catch (err) {
        return res.status(500).send({
            detail: err.message
        });
    }
    
});

exports.get_gallery_photo = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    try {
        // Get gallery photo by id
        const galleryPhoto = await GalleryPhotoSchema.findById(req.params.id);

        // Check if gallery photo exists
        if (!galleryPhoto)
            return res.status(404).send({
                detail: 'Gallery photo not found.'
            });

        // Get JWT token (bearer) from authorization header
        const header = req.headers['authorization'];
        let token = null;

        // Extract token from either header or cookie
        if (typeof header !== 'undefined') {
            // Extract token from header
            const bearer = header.split(' ');
            token = bearer[1];
        } else {
            // Extract token from cookie
            if(req.cookies['JWT_token']){
                token = req.cookies['JWT_token'];
            } else {
                // If the gallery photo is active, send the gallery photo
                if (galleryPhoto.active) {
                    const galleryPhotoDTO = {
                        id: galleryPhoto._id,
                        name: galleryPhoto.name,
                        picture: galleryPhoto.picture,
                        description: galleryPhoto.description
                    };

                    return res.status(200).send(galleryPhotoDTO);
                } else {
                    return res.status(404).send({
                        detail: 'Gallery photo not found.'
                    });
                }
            }
        }

        req.token = token;

        // Check if the token is blacklisted
        const blacklistedToken = await BlacklistedTokenSchema.findOne({ token: token });

        // JWT token is blacklisted
        if (blacklistedToken) {
            if (galleryPhoto.active) {
                const galleryPhotoDTO = {
                    id: galleryPhoto._id,
                    name: galleryPhoto.name,
                    picture: galleryPhoto.picture,
                    description: galleryPhoto.description
                };

                return res.status(200).send(galleryPhotoDTO);
            } else {
                return res.status(404).send({
                    detail: 'Gallery photo not found.'
                });
            }
        }
        
        // Check if the token is valid
        jwt.verify(req.token, process.env.JWT_SECRET, async (err, authorizedData) => {
            if (err) {
                // --------------------------------------------------
                // Handle when JWT token is expired or invalid
                // --------------------------------------------------

                // Decode JWT token
                const decodedJWT = jwt.decode(req.token, { complete: true });

                // If JWT is expired refresh token if it expired by 5 minutes (max 5 minutes of inactivity)
                if (err && !(err.name === 'TokenExpiredError' && decodedJWT.payload.exp + 300 >= (Date.now()/1000))){
                    // Blacklist previous token
                    const blacklistedToken = new BlacklistedTokenSchema({
                        token: req.token,
                        expire_at: new Date().setTime((decodedJWT.payload.exp * 1000) + 300000)
                    });

                    // Save blacklisted token in database
                    await blacklistedToken.save();

                    // Refresh JWT token
                    const userDTO = decodedJWT.payload.userDTO;
                    const newToken = jwt.sign({ userDTO }, process.env.JWT_SECRET, { expiresIn: 300 });

                    // Erase previous token
                    res.clearCookie('JWT_token');

                    // Set token in 'JWT_token' cookie
                    res.cookie('JWT_token', newToken, { httpOnly: true, secure: true });

                    // Build DTO for authenticated users
                    const photoGalleryDTO = {
                        id: galleryPhoto._id,
                        name: galleryPhoto.name,
                        picture: galleryPhoto.picture,
                        description: galleryPhoto.description,
                        uploaded_at: galleryPhoto.uploaded_at,
                        uploaded_by: galleryPhoto.uploaded_by,
                        updated_at: galleryPhoto.updated_at,
                        updated_by: galleryPhoto.updated_by,
                        active: galleryPhoto.active
                    };

                    // Send gallery photo for authenticated users
                    return res.status(200).send(photoGalleryDTO);
                }

                // JWT token is invalid or has expired more than 5 minutes
                const photoGalleryDTO = {
                    id: galleryPhoto._id,
                    name: galleryPhoto.name,
                    picture: galleryPhoto.picture,
                    description: galleryPhoto.description
                }

                // Send gallery photo for unauthenticated users
                return res.status(200).send(photoGalleryDTO);

            } else {
                // Get gallery photo for authenticated users
                const photoGalleryDTO = {
                    id: galleryPhoto._id,
                    name: galleryPhoto.name,
                    picture: galleryPhoto.picture,
                    description: galleryPhoto.description,
                    uploaded_at: galleryPhoto.uploaded_at,
                    uploaded_by: galleryPhoto.uploaded_by,
                    updated_at: galleryPhoto.updated_at,
                    updated_by: galleryPhoto.updated_by,
                    active: galleryPhoto.active
                }

                // Send gallery photo for authenticated users
                return res.status(200).send(photoGalleryDTO);
            }
        });

    } catch (err) {
        return res.status(500).send({
            detail: err.message
        });
    }
});

exports.add_gallery_photo = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    try {
        // Decode JWT token to get user information of who is uploading the gallery photo
        const decodedJWT = jwt.decode(req.token, { complete: true });
        const userDTO = decodedJWT.payload.userDTO;

        // Get the file type and file extension
        const mineType = req.headers['content-type'];
        const fileTyoe = mineType.split('/')[0];
        const fileExtension = mineType.split('/')[1];

        // Check if the file type is image
        if (fileTyoe !== 'image')
            return res.status(400).send({
                message: 'Only image files are allowed.'
            });

        // Create gallery photo object
        const galleryPhoto = new GalleryPhotoSchema({
            name: null,
            picture: '/images/gallery/default.jpg',
            description: null,
            uploaded_at: new Date(),
            uploaded_by: userDTO.id,
            active: false
        });

        // Save gallery photo object in database
        const savedGalleryPhoto = await galleryPhoto.save();

        // Define the file name
        const filename = `${savedGalleryPhoto._id}.${fileExtension}`;

        // Define the file path and the picture path (the first one is for the file system and the second one is for the database)
        const filePath = `./public/images/gallery/${filename}`;
        const picturePath = `/images/gallery/${filename}`;

        // Set the file and file name as request fields
        req.file = req.body;
        req.file.filename = filename;

        // Check if the image was uploaded
        if (!req.file)
            return res.status(400).send({
                message: 'Image not uploaded!'
            });

        // Upload image to the server
        fs.writeFileSync(filePath, req.file, (err) => err && res.status(500).send({ message: err.message }));

        // Update gallery photo with file name and picture path
        const updatedGalleryPhoto = await GalleryPhotoSchema.findByIdAndUpdate(savedGalleryPhoto._id, {
            picture: picturePath,
            uploaded_at: new Date(),
            uploaded_by: userDTO.id
        }, { new: true });

        // Create Gallery Photo DTO
        const galleryPhotoDTO = {
            id: updatedGalleryPhoto._id,
            name: updatedGalleryPhoto.name,
            picture: updatedGalleryPhoto.picture,
            description: updatedGalleryPhoto.description,
            uploaded_at: updatedGalleryPhoto.uploaded_at,
            uploaded_by: updatedGalleryPhoto.uploaded_by,
            updated_at: updatedGalleryPhoto.updated_at,
            updated_by: updatedGalleryPhoto.updated_by,
            active: updatedGalleryPhoto.active
        }

        // Send gallery photo information
        return res.status(201).send(galleryPhotoDTO);

    } catch (err) {
        return res.status(500).send({
            detail: err.message
        });
    }
});

exports.publish_gallery_photo = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    // Decode JWT token
    const decodedJWT = jwt.decode(req.token, { complete: true });

    // Get user data
    const userDTO = decodedJWT.payload.userDTO;

    try {
        // Get gallery photo by id
        const galleryPhotoFound = await GalleryPhotoSchema.findById(req.params.id);

        // Check if the photo exists
        if (!galleryPhotoFound)
            return res.status(404).send({
                detail: 'Gallery photo not found.'
            });

        // Check if the photo is already published
        if (galleryPhotoFound.active)
            return res.status(304).send();

        // Publish the photo
        const galleryPhoto = await GalleryPhotoSchema.findByIdAndUpdate(req.params.id, {
            updated_at: new Date(),
            updated_by: userDTO.id,
            active: true
        }, { new: true });

        // Send sucessful response
        return res.status(200).send(galleryPhoto);

    } catch (err) {
        return res.status(500).send({
            detail: err.message
        });
    }
});

exports.hide_gallery_photo = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    // Decode JWT token
    const decodedJWT = jwt.decode(req.token, { complete: true });

    // Get user data
    const userDTO = decodedJWT.payload.userDTO;

    try {
        // Get gallery photo by id
        const galleryPhotoFound = await GalleryPhotoSchema.findById(req.params.id);

        // Check if the photo exists
        if (!galleryPhotoFound)
            return res.status(404).send({
                detail: 'Gallery photo not found.'
            });

        // Check if the photo is already hidden
        if (!galleryPhotoFound.active)
            return res.status(304).send();

        // Hide the photo
        const galleryPhotoPublished = await GalleryPhotoSchema.findByIdAndUpdate(req.params.id, {
            updated_at: new Date(),
            updated_by: userDTO.id,
            active: false
        }, { new: true });

        // Send sucessful response
        return res.status(200).send(galleryPhotoPublished);
    } catch (err) {
        return res.status(500).send({
            detail: err.message
        });
    }
});

exports.update_gallery_photo = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    // Decode JWT token
    const decodedJWT = jwt.decode(req.token, { complete: true });

    // Get user data
    const userDTO = decodedJWT.payload.userDTO;

    try {
        // Get gallery photo by id
        const galleryPhotoFound = await GalleryPhotoSchema.findById(req.params.id);

        // Check if the photo exists
        if (!galleryPhotoFound)
            return res.status(404).send({
                detail: 'Gallery photo not found.'
            });

        // Update gallery photo
        const updatedGalleryPhoto = await GalleryPhotoSchema.findByIdAndUpdate(req.params.id, {
            name: req.body.name? req.body.name:galleryPhotoFound.name,
            description: req.body.description? req.body.description:galleryPhotoFound.description,
            updated_at: new Date(),
            updated_by: userDTO.id
        }, { new: true });

        // Send sucessful response
        return res.status(200).send(updatedGalleryPhoto);

    } catch (err) {
        return res.status(500).send({
            detail: err.message
        });
    }
});

exports.delete_gallery_photo = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    try {
        const deletedGalleryPhoto = await GalleryPhotoSchema.findByIdAndDelete(req.params.id);

        // Check if the photo exists
        if (!deletedGalleryPhoto)
            return res.status(404).send({
                detail: 'Gallery photo not found.'
            });

        // Erase photo from the server
        fs.unlinkSync(`./public${deletedGalleryPhoto.picture}`, (err) => err && res.status(500).send({ message: err.message }));

        return res.status(204).send();

    } catch (err) {
        return res.status(500).send({
            detail: err.message
        });
    }
});
