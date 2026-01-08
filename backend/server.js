// Import required packages
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Create Express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Secret key for JWT
const JWT_SECRET = 'your_secret_key_change_this_in_production';

// Database connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'aashu',
  database: 'hospital_db'
});

// Connect to database
db.connect((err) => {
  if (err) {
    console.log('❌ Database connection failed:', err.message);
  } else {
    console.log('✅ Connected to MySQL Database!');
  }
});

// Convert callback-based queries to promises
const query = (sql, params) => {
  return new Promise((resolve, reject) => {
    db.query(sql, params, (err, results) => {
      if (err) reject(err);
      else resolve(results);
    });
  });
};

// Test route
app.get('/api/test', (req, res) => {
  res.json({ 
    message: '🎉 Congratulations! Your backend is working!',
    timestamp: new Date()
  });
});

// ============================================
// AUTHENTICATION ROUTES
// ============================================

// PUBLIC REGISTRATION - PATIENTS ONLY
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, phone, password, role } = req.body;

    // SECURITY: Only patients can self-register
    if (role !== 'patient') {
      return res.status(403).json({ 
        success: false, 
        message: 'Unauthorized. Only patients can self-register.' 
      });
    }

    if (!name || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Please fill all required fields' 
      });
    }

    const existingUser = await query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUser.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email already registered' 
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await query(
      'INSERT INTO users (name, email, phone, password, role) VALUES (?, ?, ?, ?, ?)',
      [name, email, phone, hashedPassword, 'patient']
    );

    const userId = result.insertId;
    await query('INSERT INTO patients (user_id) VALUES (?)', [userId]);

    res.json({ 
      success: true, 
      message: 'Registration successful! Please login.',
      userId: userId
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during registration' 
    });
  }
});

// LOGIN - ALL ROLES
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Please provide email and password' 
      });
    }

    const users = await query('SELECT * FROM users WHERE email = ?', [email]);
    
    if (users.length === 0) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid email or password' 
      });
    }

    const user = users[0];

    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid email or password' 
      });
    }

    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email, 
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ 
      success: true, 
      message: 'Login successful!',
      token: token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during login' 
    });
  }
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  
  if (!token) {
    return res.status(403).json({ 
      success: false, 
      message: 'No token provided' 
    });
  }

  const actualToken = token.startsWith('Bearer ') ? token.slice(7) : token;

  jwt.verify(actualToken, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid or expired token' 
      });
    }
    req.user = decoded;
    next();
  });
};

// Middleware to check if user is Admin
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ 
      success: false, 
      message: 'Access denied. Admin only.' 
    });
  }
  next();
};

app.get('/api/dashboard', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const role = req.user.role;

    const users = await query('SELECT id, name, email, role FROM users WHERE id = ?', [userId]);
    const user = users[0];

    res.json({
      success: true,
      message: `Welcome to ${role} dashboard!`,
      user: user
    });

  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error' 
    });
  }
});

// ============================================
// ADMIN ROUTES
// ============================================

// Add Doctor (Admin only)
app.post('/api/admin/add-doctor', verifyToken, isAdmin, async (req, res) => {
  try {
    const { name, email, phone, specialization, qualification, experience_years, consultation_fee } = req.body;

    if (!name || !email || !specialization) {
      return res.status(400).json({ 
        success: false, 
        message: 'Please fill all required fields' 
      });
    }

    const existingUser = await query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUser.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email already exists' 
      });
    }

    const tempPassword = 'Doctor@' + Math.random().toString(36).slice(-8);
    const hashedPassword = await bcrypt.hash(tempPassword, 10);

    const result = await query(
      'INSERT INTO users (name, email, phone, password, role) VALUES (?, ?, ?, ?, ?)',
      [name, email, phone, hashedPassword, 'doctor']
    );

    const userId = result.insertId;

    await query(
      'INSERT INTO doctors (user_id, specialization, qualification, experience_years, consultation_fee) VALUES (?, ?, ?, ?, ?)',
      [userId, specialization, qualification, experience_years, consultation_fee]
    );

    res.json({ 
      success: true, 
      message: 'Doctor added successfully!',
      tempPassword: tempPassword,
      doctorId: userId
    });

  } catch (error) {
    console.error('Add doctor error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error' 
    });
  }
});

// Get all appointments (Admin only)
app.get('/api/admin/appointments', verifyToken, isAdmin, async (req, res) => {
  try {
    const appointments = await query(`
      SELECT 
        a.id,
        a.appointment_date,
        a.appointment_time,
        a.status,
        a.consultation_fee,
        a.payment_status,
        patient_user.name as patient_name,
        patient_user.phone as patient_phone,
        doctor_user.name as doctor_name,
        d.specialization
      FROM appointments a
      JOIN patients p ON a.patient_id = p.id
      JOIN users patient_user ON p.user_id = patient_user.id
      JOIN doctors d ON a.doctor_id = d.id
      JOIN users doctor_user ON d.user_id = doctor_user.id
      ORDER BY a.appointment_date DESC, a.appointment_time DESC
    `);

    res.json({
      success: true,
      appointments: appointments
    });

  } catch (error) {
    console.error('Get all appointments error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching appointments' 
    });
  }
});

// ============================================
// DOCTOR ROUTES
// ============================================

app.get('/api/doctors', async (req, res) => {
  try {
    const doctors = await query(`
      SELECT 
        d.id,
        u.name,
        d.specialization,
        d.qualification,
        d.experience_years,
        d.consultation_fee,
        d.available_days,
        d.start_time,
        d.end_time
      FROM doctors d
      JOIN users u ON d.user_id = u.id
      WHERE u.role = 'doctor'
    `);

    res.json({
      success: true,
      doctors: doctors
    });

  } catch (error) {
    console.error('Get doctors error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching doctors' 
    });
  }
});

app.get('/api/doctors/:id', async (req, res) => {
  try {
    const doctorId = req.params.id;

    const doctors = await query(`
      SELECT 
        d.id,
        u.name,
        u.email,
        u.phone,
        d.specialization,
        d.qualification,
        d.experience_years,
        d.consultation_fee,
        d.available_days,
        d.start_time,
        d.end_time,
        d.slot_duration
      FROM doctors d
      JOIN users u ON d.user_id = u.id
      WHERE d.id = ?
    `, [doctorId]);

    if (doctors.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Doctor not found' 
      });
    }

    res.json({
      success: true,
      doctor: doctors[0]
    });

  } catch (error) {
    console.error('Get doctor error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching doctor details' 
    });
  }
});

// Get doctor's appointments
app.get('/api/doctor/appointments', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    if (req.user.role !== 'doctor') {
      return res.status(403).json({ 
        success: false, 
        message: 'Only doctors can view their appointments' 
      });
    }

    const doctors = await query('SELECT id FROM doctors WHERE user_id = ?', [userId]);
    
    if (doctors.length === 0) {
      return res.status(403).json({ 
        success: false, 
        message: 'Doctor profile not found' 
      });
    }

    const doctorId = doctors[0].id;

    const appointments = await query(`
      SELECT 
        a.id,
        a.appointment_date,
        a.appointment_time,
        a.status,
        a.consultation_fee,
        a.payment_status,
        u.name as patient_name,
        u.phone as patient_phone,
        u.email as patient_email
      FROM appointments a
      JOIN patients p ON a.patient_id = p.id
      JOIN users u ON p.user_id = u.id
      WHERE a.doctor_id = ?
      ORDER BY a.appointment_date DESC, a.appointment_time DESC
    `, [doctorId]);

    res.json({
      success: true,
      appointments: appointments
    });

  } catch (error) {
    console.error('Get doctor appointments error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching appointments' 
    });
  }
});

// ============================================
// APPOINTMENT BOOKING ROUTES
// ============================================

app.get('/api/doctors/:doctorId/slots/:date', async (req, res) => {
  try {
    const { doctorId, date } = req.params;

    const doctors = await query(
      'SELECT start_time, end_time, slot_duration FROM doctors WHERE id = ?',
      [doctorId]
    );

    if (doctors.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Doctor not found' 
      });
    }

    const doctor = doctors[0];
    
    const bookedSlots = await query(
      `SELECT slot_time FROM doctor_slots 
       WHERE doctor_id = ? AND slot_date = ? 
       AND (is_booked = TRUE OR (locked_until IS NOT NULL AND locked_until > NOW()))`,
      [doctorId, date]
    );

    const bookedTimes = bookedSlots.map(slot => slot.slot_time);

    const slots = [];
    const startHour = parseInt(doctor.start_time.split(':')[0]);
    const endHour = parseInt(doctor.end_time.split(':')[0]);
    const slotDuration = doctor.slot_duration;

    for (let hour = startHour; hour < endHour; hour++) {
      for (let minute = 0; minute < 60; minute += slotDuration) {
        const timeStr = `${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}:00`;
        const isBooked = bookedTimes.some(bookedTime => bookedTime === timeStr);
        
        slots.push({
          time: timeStr,
          available: !isBooked
        });
      }
    }

    res.json({
      success: true,
      slots: slots
    });

  } catch (error) {
    console.error('Get slots error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching available slots' 
    });
  }
});

app.post('/api/slots/lock', verifyToken, async (req, res) => {
  try {
    const { doctorId, date, time } = req.body;
    const userId = req.user.userId;

    const patients = await query('SELECT id FROM patients WHERE user_id = ?', [userId]);
    
    if (patients.length === 0) {
      return res.status(403).json({ 
        success: false, 
        message: 'Only patients can book appointments' 
      });
    }

    const patientId = patients[0].id;

    const existingSlots = await query(
      `SELECT * FROM doctor_slots 
       WHERE doctor_id = ? AND slot_date = ? AND slot_time = ?
       AND (is_booked = TRUE OR (locked_until IS NOT NULL AND locked_until > NOW()))`,
      [doctorId, date, time]
    );

    if (existingSlots.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Slot is no longer available' 
      });
    }

    const lockUntil = new Date(Date.now() + 5 * 60 * 1000);

    await query(
      `INSERT INTO doctor_slots (doctor_id, slot_date, slot_time, locked_until, patient_id)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE locked_until = ?, patient_id = ?`,
      [doctorId, date, time, lockUntil, patientId, lockUntil, patientId]
    );

    res.json({
      success: true,
      message: 'Slot locked for 5 minutes',
      lockedUntil: lockUntil
    });

  } catch (error) {
    console.error('Lock slot error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error locking slot' 
    });
  }
});

app.post('/api/appointments/confirm', verifyToken, async (req, res) => {
  try {
    const { doctorId, date, time, paymentId } = req.body;
    const userId = req.user.userId;

    const patients = await query('SELECT id FROM patients WHERE user_id = ?', [userId]);
    const patientId = patients[0].id;

    const doctors = await query('SELECT consultation_fee FROM doctors WHERE id = ?', [doctorId]);
    const consultationFee = doctors[0].consultation_fee;

    await query(
      `UPDATE doctor_slots 
       SET is_booked = TRUE, locked_until = NULL 
       WHERE doctor_id = ? AND slot_date = ? AND slot_time = ? AND patient_id = ?`,
      [doctorId, date, time, patientId]
    );

    const result = await query(
      `INSERT INTO appointments 
       (patient_id, doctor_id, appointment_date, appointment_time, status, consultation_fee, payment_status, payment_id)
       VALUES (?, ?, ?, ?, 'confirmed', ?, 'paid', ?)`,
      [patientId, doctorId, date, time, consultationFee, paymentId]
    );

    res.json({
      success: true,
      message: 'Appointment confirmed successfully!',
      appointmentId: result.insertId
    });

  } catch (error) {
    console.error('Confirm appointment error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error confirming appointment' 
    });
  }
});

app.get('/api/appointments/my', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const patients = await query('SELECT id FROM patients WHERE user_id = ?', [userId]);
    
    if (patients.length === 0) {
      return res.status(403).json({ 
        success: false, 
        message: 'Only patients can view appointments' 
      });
    }

    const patientId = patients[0].id;

    const appointments = await query(`
      SELECT 
        a.id,
        a.appointment_date,
        a.appointment_time,
        a.status,
        a.consultation_fee,
        a.payment_status,
        u.name as doctor_name,
        d.specialization
      FROM appointments a
      JOIN doctors d ON a.doctor_id = d.id
      JOIN users u ON d.user_id = u.id
      WHERE a.patient_id = ?
      ORDER BY a.appointment_date DESC, a.appointment_time DESC
    `, [patientId]);

    res.json({
      success: true,
      appointments: appointments
    });

  } catch (error) {
    console.error('Get appointments error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching appointments' 
    });
  }
});

app.post('/api/appointments/:id/cancel', verifyToken, async (req, res) => {
  try {
    const appointmentId = req.params.id;
    const userId = req.user.userId;
    const { reason } = req.body;

    const patients = await query('SELECT id FROM patients WHERE user_id = ?', [userId]);
    const patientId = patients[0].id;

    const appointments = await query(
      'SELECT * FROM appointments WHERE id = ? AND patient_id = ?',
      [appointmentId, patientId]
    );

    if (appointments.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Appointment not found' 
      });
    }

    const appointment = appointments[0];

    await query(
      `UPDATE appointments 
       SET status = 'cancelled', cancelled_by = 'patient', cancellation_reason = ?, refund_status = 'completed'
       WHERE id = ?`,
      [reason || 'Cancelled by patient', appointmentId]
    );

    await query(
      `DELETE FROM doctor_slots 
       WHERE doctor_id = ? AND slot_date = ? AND slot_time = ?`,
      [appointment.doctor_id, appointment.appointment_date, appointment.appointment_time]
    );

    res.json({
      success: true,
      message: 'Appointment cancelled. Refund will be processed.'
    });

  } catch (error) {
    console.error('Cancel appointment error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error cancelling appointment' 
    });
  }
});

// ============================================
// PRESCRIPTION ROUTES
// ============================================

app.get('/api/prescriptions/my', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const patients = await query('SELECT id FROM patients WHERE user_id = ?', [userId]);
    
    if (patients.length === 0) {
      return res.status(403).json({ 
        success: false, 
        message: 'Only patients can view medical history' 
      });
    }

    const patientId = patients[0].id;

    const prescriptions = await query(`
      SELECT 
        p.id,
        p.medicines,
        p.dosage,
        p.duration,
        p.remarks,
        p.problem_description,
        p.diagnosis,
        p.advice,
        p.created_at,
        a.appointment_date,
        a.appointment_time,
        u.name as doctor_name,
        d.specialization
      FROM prescriptions p
      JOIN appointments a ON p.appointment_id = a.id
      JOIN doctors d ON a.doctor_id = d.id
      JOIN users u ON d.user_id = u.id
      WHERE p.patient_id = ?
      ORDER BY p.created_at DESC
    `, [patientId]);

    res.json({
      success: true,
      prescriptions: prescriptions
    });

  } catch (error) {
    console.error('Get prescriptions error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching medical history' 
    });
  }
});

app.post('/api/prescriptions/create', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { 
      appointmentId, 
      medicines, 
      dosage, 
      duration, 
      remarks, 
      problemDescription, 
      diagnosis, 
      advice 
    } = req.body;

    if (req.user.role !== 'doctor') {
      return res.status(403).json({ 
        success: false, 
        message: 'Only doctors can create prescriptions' 
      });
    }

    const doctors = await query('SELECT id FROM doctors WHERE user_id = ?', [userId]);
    const doctorId = doctors[0].id;

    const appointments = await query(
      'SELECT patient_id, doctor_id FROM appointments WHERE id = ?',
      [appointmentId]
    );

    if (appointments.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Appointment not found' 
      });
    }

    const appointment = appointments[0];

    if (appointment.doctor_id !== doctorId) {
      return res.status(403).json({ 
        success: false, 
        message: 'You can only create prescriptions for your own patients' 
      });
    }

    const existing = await query(
      'SELECT id FROM prescriptions WHERE appointment_id = ?',
      [appointmentId]
    );

    if (existing.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Prescription already exists for this appointment' 
      });
    }

    const result = await query(
      `INSERT INTO prescriptions 
       (appointment_id, patient_id, doctor_id, medicines, dosage, duration, remarks, problem_description, diagnosis, advice)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [appointmentId, appointment.patient_id, doctorId, medicines, dosage, duration, remarks, problemDescription, diagnosis, advice]
    );

    await query(
      'UPDATE appointments SET status = "completed" WHERE id = ?',
      [appointmentId]
    );

    res.json({
      success: true,
      message: 'Prescription created successfully',
      prescriptionId: result.insertId
    });

  } catch (error) {
    console.error('Create prescription error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error creating prescription' 
    });
  }
});

// Start server
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
  console.log(`📡 Test your API at: http://localhost:${PORT}/api/test`);
  console.log(`🔐 Secure authentication system active!`);
  console.log(`📅 Appointment booking system ready!`);
  console.log(`⚠️  SECURITY: Only patients can self-register!`);
});
