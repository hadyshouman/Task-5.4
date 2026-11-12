import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import rateLimit from 'express-rate-limit';
import {
  getAllRequests,
  getRequest,
  createRequest,
  updateRequest,
  deleteRequest
} from '../controllers/maintenanceController.js';

const router = Router();
const maintenanceLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { message: 'Too many maintenance requests. Please try again later.' }
});
router.use(maintenanceLimiter);

// Reading is public; writing requires a logged-in user.
//
// VULNERABLE on two fronts:
//   1. CSRF — the write routes trust the auth cookie alone. There is no
//      anti-CSRF token, so any website the victim visits can forge a
//      state-changing request in the victim's name (the browser attaches the
//      cookie automatically).
//   2. DoS — there is no rate limiting anywhere, so the public list endpoint
//      (and the writes) can be flooded with unlimited requests to exhaust the
//      server.
router.get('/', getAllRequests);
router.get('/:id', getRequest);
router.post('/', requireAuth, (req, res, next) => req.app.locals.doubleCsrfProtection(req, res, next), createRequest);
router.patch('/:id', requireAuth, (req, res, next) => req.app.locals.doubleCsrfProtection(req, res, next), updateRequest);
router.delete('/:id', requireAuth, (req, res, next) => req.app.locals.doubleCsrfProtection(req, res, next), deleteRequest);

export default router;
