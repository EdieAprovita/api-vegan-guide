import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Document } from "mongoose";
import * as bcrypt from "bcryptjs";

export type UserDocument = User &
	Document & {
		matchPassword: (enteredPassword: string) => Promise<boolean>;
	};

@Schema({ timestamps: true })
export class User {
	@Prop({ required: true, unique: true })
	username: string;

	@Prop({ required: true })
	password: string;

	@Prop()
	passwordResetToken?: string;

	@Prop()
	passwordResetExpires?: Date;

	@Prop({ required: true, enum: ["user", "professional"], default: "user" })
	role: "user" | "professional";

	@Prop({ required: true, default: false })
	isAdmin: boolean;

	@Prop({ required: true, unique: true, lowercase: true })
	email: string;

	@Prop({
		default:
			"https://res.cloudinary.com/dzqbzqgjm/image/upload/v1599098981/default-user_qjqjqz.png",
	})
	photo: string;
}

export const UserSchema = SchemaFactory.createForClass(User);

UserSchema.pre<UserDocument>("save", async function (next) {
	if (this.isModified("password")) {
		this.password = await bcrypt.hash(
			this.password,
			parseInt(process.env.BCRYPT_SALT_ROUNDS || "10")
		);
	}
	next();
});

UserSchema.methods.matchPassword = async function (
	enteredPassword: string
): Promise<boolean> {
	return await bcrypt.compare(enteredPassword, this.password);
};
