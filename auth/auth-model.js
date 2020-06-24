const db = require("../database/dbConfig.js");

module.exports = {
   add,
   find,
   findBy, 
   findById,
};

async function add(user) {
    try {
        const [id] = await db("users")
         .insert(user, "id");

        return findById(id)
    
    } catch (error) {
         throw error;
    }
}

function find() {
    return db("users")
      .select("id","username")
      .orderBy("id");
}

function findBy(username) {
    return db("users")
      .where(username)
     // .orderBy("id");
}

function findById(id) {
    return db("users")
      .where({id})
      .first();
}