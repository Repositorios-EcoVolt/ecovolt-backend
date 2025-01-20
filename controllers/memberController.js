const asyncHandler = require('express-async-handler');
const fs = require('fs');

const member = require('../models/member');

exports.get_members = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    try {
        const members = await member.find();

        const membersDTO = members.map((member) => {
            return {
                id: member._id,
                first_name: member.first_name,
                last_name: member.last_name,
                picture: member.picture,
                information: member.information,
                joined_at: member.joined_at,
                ended_at: member.ended_at,
                uploaded_at: member.uploaded_at,
                updated_at: member.updated_at
            }
        });

        res.status(200).send(membersDTO);
    } catch (err) {
        res.status(500).send({
            detail: err.message
        });
    }
});

exports.get_member = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    try {
        const memberFound = await member.findById(req.params.id);

        if (!memberFound) {
            return res.status(404).send({ message: 'Member not found.' });
        }

        const memberDTO = {
            id: memberFound._id,
            first_name: memberFound.first_name,
            last_name: memberFound.last_name,
            picture: memberFound.picture,
            information: memberFound.information,
            joined_at: memberFound.joined_at,
            ended_at: memberFound.ended_at,
            uploaded_at: memberFound.uploaded_at,
            updated_at: memberFound.updated_at
        };

        res.status(200).send(memberDTO);
    } catch (err) {
        res.status(500).send({
            detail: err.message
        });
    }
});

exports.add_member = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    try {
        const newMember = new member({
            first_name: req.body.first_name,
            last_name: req.body.last_name,
            picture: req.body.picture? req.body.picture:null,
            information: req.body.information,
            joined_at: req.body.joined_at? req.body.joined_at:null,
            ended_at: req.body.ended_at? req.body.ended_at:null,
            uploaded_at: new Date(),
            updated_at: null
        });

        const savedMember = await newMember.save();

        res.status(201).send(savedMember);
    } catch (err) {
        res.status(500).send({
            detail: err.message
        });
    }
});

exports.add_member_picture = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    // Get the file type and file extension
    const mimeType = req.headers['content-type'];
    const fileType = mimeType.split('/')[0];
    const fileExtension = mimeType.split('/')[1];

    // Check if the file is an image (content-type: image)
    if (fileType !== 'image')
        return res.status(400).send({ message: 'Only images are allowed.' });
    
    // Define the file name
    const filename = `${req.params.id}.${fileExtension}`;

    // Define the file path and the picture path (the first for the server file system and the second to show in the database)
    const filePath = `./public/images/members/${filename}`;
    const picturePath = `/images/members/${filename}`;

    // Set the file and file name as request fields
    req.file = req.body;
    req.file.filename = filename;

    try{
        // Check if the image was uploaded
        if (!req.file)
            return res.status(400).send({ message: 'File not uploaded!' });

        // Upload image to the server
        fs.writeFileSync(filePath, req.file, (err) => err && res.status(500).send({ message: err.message }));

        // Search member by id
        const updatedMember = await member.findByIdAndUpdate(req.params.id, { picture: picturePath, updated_at: new Date() }, { new: true });

        // Check if the member exists
        if (!updatedMember)
            return res.status(404).send({ message: 'Member not found.' });

        // Create member DTO
        const memberDTO = {
            id: updatedMember._id,
            first_name: updatedMember.first_name,
            last_name: updatedMember.last_name,
            picture: updatedMember.picture,
            information: updatedMember.information,
            joined_at: updatedMember.joined_at,
            ended_at: updatedMember.ended_at,
            uploaded_at: updatedMember.uploaded_at,
            updated_at: updatedMember.updated_at
        };

        // Send the updated member information
        res.status(200).send(memberDTO);
    } catch (err) {
        res.status(500).send({
            detail: err.message
        });
    }
});

exports.delete_member_picture = asyncHandler(async (req, res, next) => {
    try{
        // Search the member by id
        const memberFound = await member.findById(req.params.id);

        // Check if the member exists
        if (!memberFound)
            return res.status(404).send({ message: 'Member not found.' });

        // Erase picture from the server
        fs.unlinkSync(`./public${memberFound.picture}`, (err) => err && res.status(500).send({ message: err.message }));

        // Update the picture field to null
        const updatedMember = await member.findByIdAndUpdate(req.params.id, { picture: null, updated_at: new Date() }, { new: true });
        
        // Inform the client that the picture was removed
        res.status(204).send();
    } catch (err) {
        res.status(500).send({
            detail: err.message
        });
    }
});

exports.update_member = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    // Get the previous information about the member
    const memberFound = await member.findById(req.params.id);

    // Check if the member exists
    if (!memberFound) {
        return res.status(404).send({ message: 'Member not found.' });
    }

    try {
        // Update member information
        const updatedMember = await member.findByIdAndUpdate(req.params.id, {
            first_name: req.body.first_name? req.body.first_name:memberFound.first_name,
            last_name: req.body.last_name? req.body.last_name:memberFound.last_name,
            information: req.body.information? req.body.information:memberFound.information,
            joined_at: req.body.joined_at? req.body.joined_at:memberFound.joined_at,
            ended_at: req.body.ended_at? req.body.ended_at:memberFound.ended_at,
            updated_at: new Date()
        }, { new: true });

        // Send the uploaded member information
        res.status(200).send(updatedMember);
    } catch (err) {
        res.status(500).send({
            detail: err.message
        });
    }
});

exports.delete_member = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    try {
        const deletedMember = await member.findByIdAndDelete(req.params.id);

        if (!deletedMember) {
            return res.status(404).send({ message: 'Member not found.' });
        }

        res.status(204).send();
    } catch (err) {
        res.status(500).send({
            detail: err.message
        });
    }
});
