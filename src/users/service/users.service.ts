// src/users/users.service.ts
import {
	Injectable,
	NotFoundException,
	BadRequestException,
	UnauthorizedException,
} from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { User, UserDocument } from "../schemas/user.schema";
import * as jwt from "jsonwebtoken";
import * as nodemailer from "nodemailer";

@Injectable()
export class UsersService {
	constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

	async register(userData: Partial<User>): Promise<User> {
		const existingUser = await this.userModel.findOne({ email: userData.email });
		if (existingUser) {
			throw new BadRequestException("User already exists");
		}
		const user = new this.userModel(userData);
		return user.save();
	}

	async login(email: string, password: string): Promise<User> {
		const user = (await this.userModel
			.findOne({ email })
			.select("+password")) as UserDocument;
		if (!user || !(await user.matchPassword(password))) {
			throw new UnauthorizedException("Invalid credentials");
		}
		return user;
	}

	async findAll(): Promise<User[]> {
		return this.userModel.find().exec();
	}

	async findById(userId: string): Promise<User> {
		const user = await this.userModel.findById(userId).exec();
		if (!user) {
			throw new NotFoundException("User not found");
		}
		return user;
	}

	async update(userId: string, updateData: Partial<User>): Promise<User> {
		const user = (await this.userModel.findById(userId).exec()) as UserDocument;
		if (!user) {
			throw new NotFoundException("User not found");
		}
		Object.assign(user, updateData);
		return user.save();
	}

	async delete(userId: string): Promise<{ message: string }> {
		await this.userModel.findByIdAndDelete(userId).exec();
		return { message: "User deleted successfully" };
	}

	async forgotPassword(email: string): Promise<void> {
		const user = await this.userModel.findOne({ email });
		if (!user) {
			throw new NotFoundException("User not found");
		}
		const resetToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
			expiresIn: "1h",
		});
		const transporter = nodemailer.createTransport({
			service: "gmail",
			auth: {
				user: process.env.EMAIL_USER,
				pass: process.env.EMAIL_PASS,
			},
		});
		await transporter.sendMail({
			from: process.env.EMAIL_USER,
			to: user.email,
			subject: "Password reset request",
			text: `Click on the link to reset your password: ${process.env.CLIENT_URL}/reset-password/${resetToken}`,
		});
		user.passwordResetToken = resetToken;
		user.passwordResetExpires = new Date(Date.now() + 3600000);
		await user.save();
	}

	async resetPassword(token: string, newPassword: string): Promise<void> {
		const decoded = jwt.verify(token, process.env.JWT_SECRET) as { userId: string };
		const user = await this.userModel.findById(decoded.userId).exec();
		if (
			!user ||
			user.passwordResetToken !== token ||
			user.passwordResetExpires < new Date()
		) {
			throw new BadRequestException("Invalid or expired token");
		}
		user.password = newPassword;
		user.passwordResetToken = undefined;
		user.passwordResetExpires = undefined;
		await user.save();
	}
}
