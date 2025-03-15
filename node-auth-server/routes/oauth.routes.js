import express from 'express';
import oauthController from '../controllers/oauth.controller.js';
import { validate } from '../middleware/validator.js';
import { oauthValidation } from '../utils/validation.js';
import authenticate from '../middleware/auth.js';

const router = express.Router();

/**
 * @route GET /api/oauth/:provider
 * @desc Initiate OAuth flow for specified provider
 * @access Public
 */
router.get(
  '/google', 
  oauthController.initiateOAuth('google')
);

router.get(
  '/facebook', 
  oauthController.initiateOAuth('facebook')
);

router.get(
  '/apple', 
  oauthController.initiateOAuth('apple')
);

router.get(
  '/line', 
  oauthController.initiateOAuth('line')
);

/**
 * @route GET /api/oauth/:provider/callback
 * @desc Handle OAuth callback for specified provider
 * @access Public
 */
router.get(
  '/google/callback', 
  oauthController.handleOAuthCallback('google')
);

router.get(
  '/facebook/callback', 
  oauthController.handleOAuthCallback('facebook')
);

router.get(
  '/apple/callback', 
  oauthController.handleOAuthCallback('apple')
);

router.get(
  '/line/callback', 
  oauthController.handleOAuthCallback('line')
);

/**
 * @route GET /api/oauth/link/:provider
 * @desc Link OAuth provider to existing account
 * @access Private
 */
router.get(
  '/link/google', 
  authenticate(),
  oauthController.initiateOAuth('google')
);

router.get(
  '/link/facebook', 
  authenticate(),
  oauthController.initiateOAuth('facebook')
);

router.get(
  '/link/apple', 
  authenticate(),
  oauthController.initiateOAuth('apple')
);

router.get(
  '/link/line', 
  authenticate(),
  oauthController.initiateOAuth('line')
);

/**
 * @route GET /api/oauth/link/:provider/callback
 * @desc Handle OAuth linking callback for specified provider
 * @access Private
 */
router.get(
  '/link/google/callback', 
  authenticate(),
  oauthController.handleOAuthLinking('google')
);

router.get(
  '/link/facebook/callback', 
  authenticate(),
  oauthController.handleOAuthLinking('facebook')
);

router.get(
  '/link/apple/callback', 
  authenticate(),
  oauthController.handleOAuthLinking('apple')
);

router.get(
  '/link/line/callback', 
  authenticate(),
  oauthController.handleOAuthLinking('line')
);

/**
 * @route DELETE /api/oauth/unlink/:provider
 * @desc Unlink OAuth provider from user account
 * @access Private
 */
router.delete(
  '/unlink/:provider',
  authenticate(),
  validate(oauthValidation.unlinkProvider),
  oauthController.unlinkOAuth
);

export default router;