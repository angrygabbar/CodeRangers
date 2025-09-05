# DecConnectHub/invoice_service.py

from fpdf import FPDF
import os

class InvoiceGenerator:
    def __init__(self, invoice):
        self.invoice = invoice
        self.pdf = FPDF()
        self.pdf.add_page()
        
        # Add a font that supports the Rupee symbol.
        # Ensure you have a DejaVuSans.ttf file in your project's root directory.
        # You can download it from: https://www.fontsquirrel.com/fonts/dejavu-sans
        font_path = os.path.join(os.path.dirname(__file__), 'DejaVuSans.ttf')
        if os.path.exists(font_path):
            self.pdf.add_font('DejaVu', '', font_path, uni=True)
            self.pdf.set_font('DejaVu', size=12)
        else:
            # Fallback to Arial if the font is not found
            self.pdf.set_font("Arial", size=12)


    def generate_pdf(self):
        self._add_header()
        self._add_company_details()
        self._add_recipient_details()
        self._add_invoice_items()
        self._add_summary()
        self._add_footer()
        # Return as bytes, FPDF handles the encoding with Unicode fonts
        return self.pdf.output(dest='S')

    def _add_header(self):
        self.pdf.set_font('DejaVu', 'B', 24)
        self.pdf.cell(0, 10, "INVOICE", 0, 1, 'R')
        self.pdf.set_font('DejaVu', '', 12)
        self.pdf.cell(0, 8, f"Invoice #: {self.invoice.invoice_number}", 0, 1, 'R')
        self.pdf.cell(0, 8, f"Date: {self.invoice.created_at.strftime('%B %d, %Y')}", 0, 1, 'R')
        self.pdf.cell(0, 8, f"Order ID: {self.invoice.order_id or 'N/A'}", 0, 1, 'R')
        self.pdf.ln(15)

    def _add_company_details(self):
        self.pdf.set_font('DejaVu', 'B', 12)
        self.pdf.cell(0, 8, "From:", 0, 1, 'L')
        self.pdf.set_font('DejaVu', '', 12)
        self.pdf.cell(0, 8, "DecConnect Hub", 0, 1, 'L')
        self.pdf.cell(0, 8, "123 Tech Park, Innovation Drive", 0, 1, 'L')
        self.pdf.cell(0, 8, "Pune, Maharashtra, 411001", 0, 1, 'L')
        self.pdf.cell(0, 8, "admin@sourcepoint.in", 0, 1, 'L')
        self.pdf.ln(10)

    def _add_recipient_details(self):
        self.pdf.set_x(110)
        self.pdf.set_font('DejaVu', 'B', 12)
        self.pdf.cell(40, 8, "Bill To:", 0, 0, 'L')
        self.pdf.cell(0, 8, "Ship To:", 0, 1, 'L')
        
        y_before = self.pdf.get_y()

        self.pdf.set_font('DejaVu', '', 12)
        # MultiCell for bill_to_address
        self.pdf.set_x(110)
        self.pdf.multi_cell(90, 8, f"{self.invoice.recipient_name}\n{self.invoice.bill_to_address}", 0, 'L')
        
        y_after_bill = self.pdf.get_y()
        self.pdf.set_y(y_before) # Reset Y to align Ship To
        
        # MultiCell for ship_to_address
        self.pdf.set_x(150)
        self.pdf.multi_cell(50, 8, f"{self.invoice.recipient_name}\n{self.invoice.ship_to_address}", 0, 'L')

        y_after_ship = self.pdf.get_y()
        self.pdf.set_y(max(y_after_bill, y_after_ship)) # Move cursor to below the taller address block
        self.pdf.ln(15)

    def _add_invoice_items(self):
        self.pdf.set_fill_color(230, 230, 230)
        self.pdf.set_font('DejaVu', 'B', 12)
        self.pdf.cell(100, 10, "Description", 1, 0, 'C', 1)
        self.pdf.cell(30, 10, "Quantity", 1, 0, 'C', 1)
        self.pdf.cell(30, 10, "Unit Price", 1, 0, 'C', 1)
        self.pdf.cell(30, 10, "Amount", 1, 1, 'C', 1)
        
        self.pdf.set_font('DejaVu', '', 12)
        for item in self.invoice.items:
            self.pdf.cell(100, 10, item.description, 1, 0)
            self.pdf.cell(30, 10, str(item.quantity), 1, 0, 'C')
            self.pdf.cell(30, 10, f"₹{item.price:.2f}", 1, 0, 'R')
            self.pdf.cell(30, 10, f"₹{item.quantity * item.price:.2f}", 1, 1, 'R')
        self.pdf.ln(10)

    def _add_summary(self):
        self.pdf.set_x(110)
        self.pdf.set_font('DejaVu', '', 12)
        self.pdf.cell(50, 8, "Subtotal:", 0, 0, 'R')
        self.pdf.cell(40, 8, f"₹{self.invoice.subtotal:.2f}", 0, 1, 'R')
        
        self.pdf.set_x(110)
        self.pdf.cell(50, 8, f"Tax ({self.invoice.tax}%):", 0, 0, 'R')
        self.pdf.cell(40, 8, f"₹{(self.invoice.subtotal * self.invoice.tax / 100):.2f}", 0, 1, 'R')
        
        self.pdf.set_x(110)
        self.pdf.set_font('DejaVu', 'B', 14)
        self.pdf.cell(50, 10, "Total:", 0, 0, 'R')
        self.pdf.cell(40, 10, f"₹{self.invoice.total_amount:.2f}", 0, 1, 'R')
        self.pdf.ln(10)

    def _add_footer(self):
        y_pos = self.pdf.get_y()
        if y_pos > 220: # Add a new page if content is too low
            self.pdf.add_page()

        self.pdf.set_font('DejaVu', 'B', 12)
        self.pdf.cell(0, 8, "Notes:", 0, 1, 'L')
        self.pdf.set_font('DejaVu', '', 12)
        self.pdf.multi_cell(0, 8, self.invoice.notes or "N/A", 0, 'L')
        self.pdf.ln(5)

        self.pdf.set_font('DejaVu', 'B', 12)
        self.pdf.cell(0, 8, "Payment Details:", 0, 1, 'L')
        self.pdf.set_font('DejaVu', '', 12)
        self.pdf.multi_cell(0, 8, self.invoice.payment_details or "N/A", 0, 'L')
        self.pdf.ln(5)

        self.pdf.set_y(-30)
        self.pdf.set_font('DejaVu', 'I', 10)
        self.pdf.cell(0, 10, f"Invoice due by {self.invoice.due_date.strftime('%B %d, %Y')}", 0, 1, 'C')

