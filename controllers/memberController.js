const asyncHandler = require('express-async-handler');
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
            picture: req.body.picture? req.body.picture:memberFound.picture,
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
