const asyncHandler = require('express-async-handler');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const informationSection = require('../models/informationSection');

exports.get_information_sections = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    try {
        const informationSections = await informationSection.find();

        const informationSectionsDTO = informationSections.map((section) => {
            return {
                id: section._id,
                title: section.title,
                subtitle: section.subtitle,
                content: section.content,
                picture: section.picture,
                created_by: section.created_by,
                updated_by: section.updated_by,
                created_at: section.created_at,
                updated_at: section.updated_at,
                active: section.active
            }
        });

        res.status(200).send(informationSectionsDTO);
    } catch (err) {
        res.status(500).send({
            detail: err.message
        });
    }
});

exports.add_information_section = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');   
    
    // Decode JWT token
    const decodedJWT = jwt.decode(req.token, { complete: true });
    
    // Get user data
    const userDTO = decodedJWT.payload.userDTO;

    try {
        const newInformationSection = new informationSection({
            title: req.body.title,
            subtitle: req.body.subtitle,
            content: req.body.content,
            created_by: userDTO.id,
            updated_by: null,
            created_at: new Date(),
            updated_at: null,
            active: false
        });


        const savedInformationSection = await newInformationSection.save();

        res.status(201).send(savedInformationSection);
    } catch (err) {
        res.status(500).send({
            detail: err.message
        });
    }
});

exports.add_information_section_picture = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    // Get the file type and extension
    const mineType = req.headers['content-type'];
    const fileType = mineType.split('/')[0];
    const extension = mineType.split('/')[1];

    // Check if the file is an image (content-type: image)
    if (fileType !== 'image')
        return res.status(400).send({ message: 'File is not an image.' });

    // Define the file name
    const filename = `${req.params.id}.${extension}`;

    // Define the file path and path to show in the database
    const filePath = `./public/images/informationSections/${filename}`;
    const picturePath = `/images/informationSections/${filename}`;

    // Set the file and file name to the request
    req.file = req.body;
    req.file.filename = filename;

    try {
        // Check if the file was uploaded
        if(!req.file) 
            return res.status(400).send({ message: 'File not uploaded!' });

        // Upload the image to the server
        fs.writeFileSync(filePath, req.file, (err) => err && res.status(500).send({ message: err.message }));

        // Search the information section by id
        const updatedInformationSection = await informationSection.findByIdAndUpdate(req.params.id, { picture: picturePath, updated_at: new Date() }, { new: true });

        // Check if the information section exists
        if (!updatedInformationSection)
            return res.status(404).send({ message: 'Information Section not found.' });

        res.status(200).send(updatedInformationSection);
    } catch (err) {
        res.status(500).send({
            detail: err.message
        });
    }
});

exports.remove_information_section_picture = asyncHandler(async (req, res, next) => {
    try {
        // Search the information section by id
        const informationSectionFound = await informationSection.findById(req.params.id);

        // Check if the information section exists
        if (!informationSectionFound)
            return res.status(404).send({ message: 'Information Section not found.' });
        
        // Erase picture from the server
        fs.unlinkSync(`./public${informationSectionFound.picture}`, (err) => err && res.status(500).send({ message: err.message }));

        // Update the information section with picture field to null
        const updatedInformationSection = await informationSection.findByIdAndUpdate(req.params.id, { picture: null, updated_at: new Date() }, { new: true });

        // Inform the client that the picture was removed
        res.status(204).send();
    } catch (err) {
        res.status(500).send({
            detail: err.message
        });
    }
});

exports.publish_information_section = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    try {
        const publishedInformationSection = await informationSection.findByIdAndUpdate(req.params.id, { active: true, updated_at: new Date() }, { new: true });

        if (!publishedInformationSection) 
            return res.status(404).send({ message: 'Information Section not found.' });
            
        res.status(200).send(publishedInformationSection);
    } catch (err) {
        res.status(500).send({
            detail: err.message
        });
    }
});

exports.hide_information_section = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    try {
        const hiddenInformationSection = await informationSection.findByIdAndUpdate(req.params.id, { active: false, updated_at: new Date() }, { new: true });

        if (!hiddenInformationSection)
            return res.status(404).send({ message: 'Information Section not found.' });
        
        res.status(200).send(hiddenInformationSection);
    } catch (err) {
        res.status(500).send({
            detail: err.message
        });
    }
});

exports.update_information_section = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    // Decode JWT token
    const decodedJWT = jwt.decode(req.token, { complete: true });
    
    // Get user data
    const userDTO = decodedJWT.payload.userDTO;

    // Get the previous information section
    const previousInformationSection = await informationSection.findById(req.params.id);

    // Check if the information section exists
    if (!previousInformationSection) 
        return res.status(404).send({ message: 'Information Section not found.' });
    
    try {
        // Update the information section
        const updatedInformationSection = await informationSection.findByIdAndUpdate(req.params.id, { 
            title: req.body.title? req.body.title:previousInformationSection.title,
            subtitle: req.body.subtitle? req.body.subtitle:previousInformationSection.subtitle, 
            content: req.body.content? req.body.content:previousInformationSection.content, 
            picture: req.body.picture? req.body.picture:previousInformationSection.picture, 
            updated_by: userDTO.id, 
            updated_at: new Date(),
            active: req.body.active? req.body.active:previousInformationSection.active
        }, { new: true });

        // Send the updated information section
        res.status(200).send(updatedInformationSection);
    } catch (err) {
        res.status(500).send({
            detail: err.message
        });
    }
});


exports.delete_information_section = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    try {
        // Try to delete the information section
        const deletedInformationSection = await informationSection.findByIdAndDelete(req.params.id);

        // Check if the information section exists
        if (!deletedInformationSection)
            return res.status(404).send({ message: 'Information Section not found.' });

        // Send a 204 response
        res.status(204).send();
    } catch (err) {
        res.status(500).send({
            detail: err.message
        });
    }
});
