import Users from '../../Core/Models/user.model.js'
import Events from '../Models/event.model.js'
import Reviews from '../Models/review.model.js'

// Sætter modellers relationelle forhold - een til mange
Users.hasMany(Reviews)
Reviews.belongsTo(Users)

Events.hasMany(Reviews)
Reviews.belongsTo(Events)

class ReviewsController {

	/**
	 * List Metode - henter alle records
	 * @param {object} req 
	 * @param {object} res 
	 * @return {array} Returnerer JSON array
	 */
	list = async (req, res) => {
		try {
			const result = await Reviews.findAll({
				attributes: ['id', 'subject', 'num_stars', 'created_at'],
				include: [{
					model: Users,
					attributes: ['firstname', 'lastname', 'email']
				}, {
					model: Events,
					attributes: ['title']
				}],
				where: { event_id: req.params.event_id }
	
			})
			// Parser resultat som json
			res.json(result)			
		} catch (error) {
			res.status(418).send({
				message: `Something went wrong: ${error}`
			})						
		}

	}

	/**
	 * GET Metode henter record ud fra id
	 * @param {object} req 
	 * @param {object} res 
	 * @return {object} Returnerer JSON object med detaljer
	 */
	details = async (req, res) => {
		const { id } = req.params

		if(id) {
			try {
				const result = await Reviews.findOne({
					attributes: ['id', 'subject', 'comment', 'num_stars', 'created_at'],
					include: [{
						model: Users,
						attributes: ['firstname', 'lastname', 'email']
					}, {
						model: Events,
						attributes: ['title']
					}],
		
					where: { id: req.params.id}
				});
				res.json(result)						
			} catch (error) {
				res.status(418).send({
					message: `Something went wrong: ${error}`
				})						
			}
		} else {
			res.status(403).send({
				message: `Wrong parameter values`
			})					
		}
	}

	/**
	 * Create Metode - opretter ny record
	 * @param {object} req Request Object
	 * @param {object} res Response Object
	 * @return {number} Returnerer nyt id
	 */
	 create = async (req, res) => {
		const { subject, comment,  num_stars, event_id } = req.body
		const user_id = req.user_id
		

		if(subject && comment && num_stars !==null && event_id !== null) {
			try {
				const model = await Reviews.create({...req.body,user_id})
				return res.json({
					message: `Record created`,
					newId: model.id
				})					
			} catch (error) {
				res.status(418).send({
					message: `Could not create record: ${error}`
				})									
			}
		} else {
			res.status(403).send({
				message: `Wrong parameter values`
			})					
		}
	}	

	/**
	 * Update Metode - opdaterer record
	 * @param {object} req Request Object
	 * @param {object} res Response Object
	 * @return {boolean} Returnerer true/false
	 */	
	 update = async (req, res) => {

		const { id, subject, comment, num_stars, is_active } = req.body

		if(id, subject && comment && num_stars && is_active) {
			try {
				const model = await Reviews.update(req.body, {
					where: {id: id}
				})
				return res.json({
					message: `Record updated`	
				})					
			} catch (error) {
				res.status(418).send({
					message: `Could not update record: ${error}`
				})				
			}
		} else {
			res.status(403).send({
				message: 'Wrong parameter values'
			})
		}
	}

	/**
	 * Delete Metode - sletter record
	 * @param {object} req Request Object
	 * @param {object} res Response Object
	 * @return {boolean} Returnerer true/false
	 */	
	remove = async (req, res) => {
		const { id } = req.params

		if(id) {
			try {
				await Reviews.destroy({ 
					where: { id: req.params.id }
				})
				res.status(200).send({
					message: `Record deleted`
				})
			}
			catch(err) {
				res.status(418).send({
					message: `Could not delete record: ${error}`
				})									
			}	
		} else {
			res.status(403).send({
				message: 'Wrong parameter values'
			})			
		}
	}	
}

export default ReviewsController