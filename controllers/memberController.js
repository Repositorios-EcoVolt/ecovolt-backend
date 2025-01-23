const asyncHandler = require('express-async-handler');
const fs = require('fs');
const jwt = require('jsonwebtoken');

const member = require('../models/member');

exports.get_members = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    // Check if the user is logged in
    jwt.verify(req.token, process.env.JWT_SECRET, async (err, authorizedData) => {
        try {
            const members = await member.find();
            let membersDTO = null;

            // If the user is not logged in, only show active members
            if (err) {
                membersDTO = members.map((member) => {
                    return {
                        id: member._id,
                        first_name: member.first_name,
                        last_name: member.last_name,
                        areas: member.areas,
                        picture: member.picture,
                        information: member.information,
                        joined_at: member.joined_at,
                        ended_at: member.ended_at,
                        uploaded_at: member.uploaded_at,
                        uoloaded_by: member.uploaded_by,
                        updated_at: member.updated_at,
                        updated_by: member.updated_by
                    }
                }).filter((member) => member.active !== false);
        
            } else {
                // If the user is logged in, show all members
                membersDTO = members.map((member) => {
                    return {
                        id: member._id,
                        first_name: member.first_name,
                        last_name: member.last_name,
                        areas: member.areas,
                        picture: member.picture,
                        information: member.information,
                        joined_at: member.joined_at,
                        ended_at: member.ended_at,
                        uploaded_at: member.uploaded_at,
                        uoloaded_by: member.uploaded_by,
                        updated_at: member.updated_at,
                        updated_by: member.updated_by,
                        active: member.active
                    }
                });
            }

            // Send members information
            res.status(200).send(membersDTO);
        } catch (err) {
            res.status(500).send({
                detail: err.message
            });
        }
    });
});

exports.get_member = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    // Check if the user is logged in
    try {
        jwt.verify(req.token, process.env.JWT_SECRET, async (err, authorizedData) => {
            const memberFound = await member.findById(req.params.id);
            let memberDTO = null;
    
            if (!memberFound)
                return res.status(404).send({ message: 'Member not found.' });
    
            // If the user is not logged in, only show active members
            if (err) {
                if (!memberFound.active)
                    return res.status(404).send({ message: 'Member not found.' });
    
                memberDTO = {
                    id: memberFound._id,
                    first_name: memberFound.first_name,
                    last_name: memberFound.last_name,
                    areas: memberFound.areas,
                    picture: memberFound.picture,
                    information: memberFound.information,
                    joined_at: memberFound.joined_at,
                    ended_at: memberFound.ended_at,
                    uploaded_at: memberFound.uploaded_at,
                    uploaded_by: memberFound.uploaded_by,
                    updated_at: memberFound.updated_at,
                    updated_by: memberFound.updated_by
                } 
    
            } else {
                // If the user is logged in, show all members
                memberDTO = {
                    id: memberFound._id,
                    first_name: memberFound.first_name,
                    last_name: memberFound.last_name,
                    areas: memberFound.areas,
                    picture: memberFound.picture,
                    information: memberFound.information,
                    joined_at: memberFound.joined_at,
                    ended_at: memberFound.ended_at,
                    uploaded_at: memberFound.uploaded_at,
                    uploaded_by: memberFound.uploaded_by,
                    updated_at: memberFound.updated_at,
                    updated_by: memberFound.updated_by,
                    active: memberFound.active
                }
            }
    
            // Send member information
            return res.status(200).send(memberDTO);
        });
    } catch (err) {
        return res.status(500).send({
            detail: err.message
        });
    }
});

exports.add_member = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    try {
        // Decode JWT token and get user information
        const decodedJWT = jwt.decode(req.token, { complete: true });
        const userDTO = decodedJWT.payload.userDTO;

        const newMember = new member({
            first_name: req.body.first_name,
            last_name: req.body.last_name,
            areas: req.body.areas,
            information: req.body.information,
            joined_at: req.body.joined_at? req.body.joined_at:null,
            ended_at: req.body.ended_at? req.body.ended_at:null,
            uploaded_at: new Date(),
            uploaded_by: userDTO.id,
            updated_at: null,
            updated_by: null,
            active: req.body.active? req.body.active:true
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

    // Decode JWT token to get user information of who is updating the member
    const decodedJWT = jwt.decode(req.token, { complete: true });
    const userDTO = decodedJWT.payload.userDTO;

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
        const updatedMember = await member.findByIdAndUpdate(req.params.id, { 
            picture: picturePath, 
            updated_at: new Date(),
            updated_by: userDTO.id
        }, { new: true });

        // Check if the member exists
        if (!updatedMember)
            return res.status(404).send({ message: 'Member not found.' });

        // Create member DTO
        const memberDTO = {
            id: updatedMember._id,
            first_name: updatedMember.first_name,
            last_name: updatedMember.last_name,
            areas: updatedMember.areas,
            picture: updatedMember.picture,
            information: updatedMember.information,
            joined_at: updatedMember.joined_at,
            ended_at: updatedMember.ended_at,
            uploaded_at: updatedMember.uploaded_at,
            uploaded_by: updatedMember.uploaded_by,
            updated_at: updatedMember.updated_at,
            updated_by: updatedMember.updated_by,
            active: updatedMember.active
        };

        // Send the updated member information
        return res.status(200).send(memberDTO);
    } catch (err) {
        return res.status(500).send({
            detail: err.message
        });
    }
});

exports.delete_member_picture = asyncHandler(async (req, res, next) => {
    try{
        // Decode JWT token to get user information of who is updating the member
        const decodedJWT = jwt.decode(req.token, { complete: true });
        const userDTO = decodedJWT.payload.userDTO;

        // Search the member by id
        const memberFound = await member.findById(req.params.id);

        // Check if the member exists
        if (!memberFound)
            return res.status(404).send({ message: 'Member not found.' });

        // Erase picture from the server
        fs.unlinkSync(`./public${memberFound.picture}`, (err) => err && res.status(500).send({ message: err.message }));

        // Update the picture field to null
        await member.findByIdAndUpdate(req.params.id, { 
            picture: null, 
            updated_at: new Date(), 
            updated_by: userDTO.id 
        }, { new: true });
        
        // Inform the client that the picture was removed
        return res.status(204).send();
    } catch (err) {
        return res.status(500).send({
            detail: err.message
        });
    }
});

exports.update_member = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    try {
        // Get the previous information about the member
        const memberFound = await member.findById(req.params.id);

        // Check if the member exists
        if (!memberFound)
            return res.status(404).send({ message: 'Member not found.' });

        // Decode JWT token and get user information
        const decodedJWT = jwt.decode(req.token, { complete: true });
        const userDTO = decodedJWT.payload.userDTO;
    
        // Update member information
        const updatedMember = await member.findByIdAndUpdate(req.params.id, {
            first_name: req.body.first_name? req.body.first_name:memberFound.first_name,
            last_name: req.body.last_name? req.body.last_name:memberFound.last_name,
            areas: req.body.areas? req.body.areas:memberFound.areas,
            information: req.body.information? req.body.information:memberFound.information,
            joined_at: req.body.joined_at? req.body.joined_at:memberFound.joined_at,
            ended_at: req.body.ended_at? req.body.ended_at:memberFound.ended_at,
            updated_at: new Date(),
            updated_by: userDTO.id,
            active: req.body.active? req.body.active:memberFound.active
        }, { new: true });

        // Send the uploaded member information
        return res.status(200).send(updatedMember);
    } catch (err) {
        return res.status(500).send({
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

        return res.status(204).send();
    } catch (err) {
        return res.status(500).send({
            detail: err.message
        });
    }
});
