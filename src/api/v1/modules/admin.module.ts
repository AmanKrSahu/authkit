import { AdminController } from '../controllers/admin.controller';
import { AdminService } from '../services/admin.service';

const adminService = new AdminService();
const adminController = new AdminController(adminService);

export { adminController, adminService };
