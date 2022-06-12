// with the help of these models mongodb will understand how it needs to structure our data inside of the database

// to encrypt password before saving user in database
// const bcrypt = require("bcryptjs");

// connector of mongodb database
const mongoose = require("mongoose");

// creating messageModel object
const userModel = mongoose.Schema(
  {
    name: { type: String, required: true },
    phone: { type: String, required: true, unique: true },
    email: { type: String, required: true },
    pic: {
      type: String,
      default:
        "https://icon-library.com/images/anonymous-avatar-icon/anonymous-avatar-icon-25.jpg",
    },
  },
  {
    // add a field so that mongoose creates the time stamp every time we create we add a new data so if a new chat is added it's going to add the time stamps
    timestamps: true,
  }
);

// userModel.methods.matchPassword = async function (enteredPassword) {
//   return await bcrypt.compare(enteredPassword, this.password);
// };

// userModel.pre("save", async function (next) {
//   if (!this.isModified) {
//     next();
//   }
//   const salt = await bcrypt.genSalt(10); // higher the number more salt will be generated
//   this.password = await bcrypt.hash(this.password, salt);
// });

// create a model named "User" by providing userModel Object
const User = mongoose.model("User", userModel);

module.exports = User;
