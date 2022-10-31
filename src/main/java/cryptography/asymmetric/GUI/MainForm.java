package cryptography.asymmetric.GUI;

import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Container;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.WindowConstants;
import javax.swing.border.Border;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.plaf.basic.BasicScrollBarUI;

public class MainForm extends JFrame {

  private JPanel mainPanel;
  private JLabel progNameLabel;
  private JLabel authorLabel;
  private JList<String> algorithmsList;
  private JScrollPane scrollPanel;
  private JPanel dataPanel;
  private JPanel menuPanel;
  private JPanel algNamePanel;
  private JLabel algNameLabel;
  private JPanel logsPanel;
  private JPanel algorithmsPanel;
  private JTextArea logsTextArea;
  private JPanel inputTypePanel;
  private JRadioButton plainTextRadioButton;
  private JRadioButton fileRadioButton;
  private JPanel outputResultPanel;
  private JTextArea outputArea;
  private JLabel resultLabel;
  private JScrollPane scrollOutputPanel;
  private JLabel outputTipLabel;
  private JPanel inputDataAndParamsPanel;
  private JPanel inputDataPanel;
  private JTextArea inputArea;
  private JButton calculateButton;
  private JLabel inputTipLabel;
  private JScrollPane scrollInputPanel;
  private JPanel calculateButtonPanel;
  private JRadioButton encryptRadioButton;
  private JRadioButton decryptRadioButton;
  private JPanel paramsPanel;
  private JPanel encryptDecryptPanel;
  private JLabel paramsTipLabel;
  private JPanel changeInputTypePanel;
  private JPanel inputFilePanel;
  private JButton chooseInputFileButton;
  private JLabel currentFileTipLabel;
  private JLabel currentFilePathLabel;
  private JLabel fileSizeTipLabel;
  private JPanel changeOutputTypePanel;
  private JPanel outputFilePanel;
  private JButton chooseOutputFileButton;
  private JLabel outputFileSizeTipLabel;
  private JLabel outputCUrrentFilePathLabel;
  private JTextField currentFilePathField;
  private JTextField outputCurrentFilePathField;
  private JPanel authorPanel;
  private JLabel githubLink;
  private JPanel linksPanel;
  private JLabel githubLabel;
  private JPanel paramsAlgorithmsPanel;
  private JPanel rsaPanel;
  private JRadioButton rsaPKCS1OAEPPaddingButton;
  private JRadioButton rsaNonePaddingButton;
  private JRadioButton autoKeyGenButton;
  private JRadioButton manualKeyGenButton;
  private JTextField rsaModulusField;
  private JLabel rsaPublicPrivateKey;
  private JTextField rsaPublicKeyField;
  private JPanel rsaEncryptDecryptPanel;
  private JTextField rsaPrivateKeyField;
  private JTextField rsaKeyLengthField;
  private JButton generateKeyButton;
  private JLabel rsaModulusLabel;
  private JPanel dhPanel;
  private JLabel rsaKeyLengthLabel;
  private JTextArea currentInputFileArea;
  private JLabel fileSizeLabel;
  private JLabel currentFileLabel;

  private final JFileChooser inputFileChooser = new JFileChooser();

  private final JFileChooser outputFileChooser = new JFileChooser();


  public MainForm() {
    super();
    setSize(new Dimension(800, 500));
    setVisible(true);
    setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
    setContentPane(mainPanel);
    scrollPanel.setPreferredSize(new Dimension(100, this.getHeight()));
    progNameLabel.setPreferredSize(new Dimension(scrollPanel.getWidth(), 40));
    authorPanel.setPreferredSize(new Dimension(scrollPanel.getWidth(), 40));
    algNamePanel.setPreferredSize(new Dimension(dataPanel.getWidth(), 40));
    logsPanel.setPreferredSize(new Dimension(dataPanel.getWidth(), 55));
    inputTypePanel.setPreferredSize(new Dimension(dataPanel.getWidth(), 40));
    outputResultPanel.setPreferredSize(new Dimension(dataPanel.getWidth(), 80));
    inputDataPanel.setPreferredSize(new Dimension(dataPanel.getWidth(), 100));
    resultLabel.setPreferredSize(new Dimension(150, outputResultPanel.getHeight()));
    calculateButtonPanel.setPreferredSize(new Dimension(150, inputDataPanel.getHeight()));
    Dimension scrollDim = new Dimension(10, 0);
    NoArrowScrollBarUI scrollArrow = new NoArrowScrollBarUI();
    scrollOutputPanel.getVerticalScrollBar().setPreferredSize(scrollDim);
    scrollInputPanel.getVerticalScrollBar().setPreferredSize(scrollDim);
    scrollPanel.getVerticalScrollBar().setPreferredSize(scrollDim);
    githubLabel.setForeground(Color.BLUE.darker());
    githubLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
    githubLabel.addMouseListener(new HyperLinkListener());
    //scrollOutputPanel.getVerticalScrollBar().setUI(scrollArrow);
    //scrollInputPanel.getVerticalScrollBar().setUI(scrollArrow);
    //scrollPanel.getVerticalScrollBar().setUI(scrollArrow);
    logsTextArea.setBackground(dataPanel.getBackground());
    algorithmsList.setBackground(dataPanel.getBackground());
    currentFilePathField.setBackground(dataPanel.getBackground());
    outputCurrentFilePathField.setBackground(dataPanel.getBackground());
    logsTextArea.setWrapStyleWord(true);
    outputArea.setWrapStyleWord(true);
    inputArea.setWrapStyleWord(true);
    logsTextArea.setLineWrap(true);
    outputArea.setLineWrap(true);
    inputArea.setLineWrap(true);
    logsTextArea.setMargin(new Insets(0, 10, 0, 10));
    outputArea.setMargin(new Insets(5, 5, 5, 5));
    inputArea.setMargin(new Insets(5, 5, 5, 5));
    calculateButton.setMargin(new Insets(25, 25, 25, 25));
    logsTextArea.getCaret().setBlinkRate(0);
    fileRadioButton.addItemListener(new InputTypeListener());
    Border emptyBorder = BorderFactory.createEmptyBorder();
    plainTextRadioButton.setBorder(emptyBorder);
    fileRadioButton.setBorder(emptyBorder);
    ChoseFileListener cfl = new ChoseFileListener();
    chooseInputFileButton.addActionListener(cfl);
    chooseOutputFileButton.addActionListener(cfl);
    logsTextArea.setText("1.Choose input/output format -> enter data according to chosen format\n2.Choose encrypt or decrypt -> set parameters\n3.Press «Calculate» button");
    scrollPanel.setBorder(BorderFactory.createMatteBorder(1, 0, 2, 0, Color.BLACK));
    menuPanel.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 2, Color.BLACK));
    algorithmsPanel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Color.BLACK));
    encryptDecryptPanel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Color.BLACK));
    outputTipLabel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Color.BLACK));
    logsTextArea.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Color.BLACK));
    outputResultPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
    paramsPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
    logsPanel.setBorder(BorderFactory.createEmptyBorder(0, 5, 5, 5));
    inputFilePanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
    currentFilePathField.setBorder(BorderFactory.createEmptyBorder());
    outputCurrentFilePathField.setBorder(BorderFactory.createEmptyBorder());
    outputFilePanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
    inputDataPanel.setBorder(BorderFactory.createEmptyBorder(0, 5, 5, 5));
    calculateButtonPanel.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));
    algNameLabel.setText(algorithmsList.getSelectedValue());
    algorithmsList.addListSelectionListener(new MenuSelectionListener());
    autoKeyGenButton.setSelected(true);
    UserSelections.currentAlgorithm = algorithmsList.getSelectedValue();
    UserSelections.keyGenAutoOrManually = autoKeyGenButton.isSelected();
    Dimension rsaKeyLabel = new Dimension(50, 10);

    //RSA
    rsaNonePaddingButton.setSelected(true);
    rsaPublicPrivateKey.setMinimumSize(rsaKeyLabel);
    rsaPublicPrivateKey.setMaximumSize(rsaKeyLabel);
    rsaPublicPrivateKey.setPreferredSize(rsaKeyLabel);
    rsaPublicKeyField.setEditable(!UserSelections.keyGenAutoOrManually);
    rsaPrivateKeyField.setEditable(!UserSelections.keyGenAutoOrManually);
    rsaModulusField.setEditable(!UserSelections.keyGenAutoOrManually);
    rsaKeyLengthField.setEditable(UserSelections.keyGenAutoOrManually);
    generateKeyButton.setEnabled(UserSelections.keyGenAutoOrManually);

    EncryptDecryptListener encryptDecryptListener = new EncryptDecryptListener();
    encryptRadioButton.addItemListener(encryptDecryptListener);
    decryptRadioButton.addItemListener(encryptDecryptListener);
    AutoManualKeyGenListener autoManualKeyGenListener = new AutoManualKeyGenListener();
    autoKeyGenButton.addItemListener(autoManualKeyGenListener);
    manualKeyGenButton.addItemListener(autoManualKeyGenListener);
  }

  private class MenuSelectionListener implements ListSelectionListener {

    @Override
    public void valueChanged(ListSelectionEvent e) {
      algNameLabel.setText("<html>" + algorithmsList.getSelectedValue() + "</html>");
      UserSelections.currentAlgorithm = algorithmsList.getSelectedValue();
      changePlane();
    }
  }

  private class AutoManualKeyGenListener implements ItemListener {

    @Override
    public void itemStateChanged(ItemEvent e) {
      JRadioButton button = (JRadioButton) e.getItem();
      if (button.isSelected()) {
        UserSelections.keyGenAutoOrManually = button.getText().equals("Auto");
        changeAutoOrManually();
      }
    }
  }

  private class EncryptDecryptListener implements ItemListener {

    @Override
    public void itemStateChanged(ItemEvent e) {
      JRadioButton button = (JRadioButton) e.getItem();
      if (button.isSelected()) {
        UserSelections.encryptOrDecrypt = button.getText();
        //UserSelections.keyGenAutoOrManually = autoKeyGenButton
        changePlane();
      }
    }
  }

  private void changePlane() {
    CardLayout cardLayout = (CardLayout) paramsAlgorithmsPanel.getLayout();
    cardLayout.show(paramsAlgorithmsPanel, UserSelections.currentAlgorithm);
    Container panel = null;
    switch (UserSelections.currentAlgorithm) {
      case "RSA" -> {
        cardLayout = (CardLayout) rsaEncryptDecryptPanel.getLayout();
        panel = rsaEncryptDecryptPanel;
      }
    }
    cardLayout.show(panel, UserSelections.encryptOrDecrypt);

    //Остальные изменения интерфейса, несвязанные с CardLayout
    changeEncryptOrDecrypt();
    changeAutoOrManually();
  }

  private void changeAutoOrManually() {
    switch (UserSelections.currentAlgorithm) {
      case "RSA" -> {
        rsaModulusField.setEditable(!UserSelections.keyGenAutoOrManually);
        rsaPublicKeyField.setEditable(!UserSelections.keyGenAutoOrManually);
        rsaPrivateKeyField.setEditable(!UserSelections.keyGenAutoOrManually);
        rsaKeyLengthField.setEditable(UserSelections.keyGenAutoOrManually);
        generateKeyButton.setEnabled(UserSelections.keyGenAutoOrManually);
      }
    }
  }

  private void changeEncryptOrDecrypt() {
    switch (UserSelections.currentAlgorithm) {
      case "RSA" -> {
        rsaPublicPrivateKey.setText(UserSelections.encryptOrDecrypt.equals("Encrypt") ? "Public key" : "Private key");
      }
    }
  }

  private class ChoseFileListener implements ActionListener {

    @Override
    public void actionPerformed(ActionEvent e) {
      int choice;
      if (e.getActionCommand().equals("InputFile")) {
        choice = inputFileChooser.showOpenDialog(mainPanel);
        if (choice == JFileChooser.APPROVE_OPTION) {
          currentFilePathField.setText(inputFileChooser.getSelectedFile().toString());
          currentFilePathField.setToolTipText(currentFilePathField.getText());
          fileSizeTipLabel.setText("Size (bytes): " + 512);
        }
      } else {
       choice = outputFileChooser.showOpenDialog(mainPanel);
        if (choice == JFileChooser.APPROVE_OPTION) {
          outputCurrentFilePathField.setText(outputFileChooser.getSelectedFile().toString());
          outputCurrentFilePathField.setToolTipText(outputCurrentFilePathField.getText());
          outputFileSizeTipLabel.setText("Size (bytes): " + 512);
        }
      }
    }
  }

  private class InputTypeListener implements ItemListener {

    @Override
    public void itemStateChanged(ItemEvent e) {
      CardLayout cl = (CardLayout) changeInputTypePanel.getLayout();
      cl.next(changeInputTypePanel);
      cl = (CardLayout) changeOutputTypePanel.getLayout();
      cl.next(changeOutputTypePanel);
    }
  }

  static class NoArrowScrollBarUI extends BasicScrollBarUI {

    protected JButton createZeroButton() {
      JButton button = new JButton("zero button");
      Dimension zeroDim = new Dimension(0, 0);
      button.setPreferredSize(zeroDim);
      button.setMinimumSize(zeroDim);
      button.setMaximumSize(zeroDim);
      return button;
    }

    @Override
    protected JButton createDecreaseButton(int orientation) {
      return createZeroButton();
    }

    @Override
    protected JButton createIncreaseButton(int orientation) {
      return createZeroButton();
    }
  }

  private class HyperLinkListener implements MouseListener {

    @Override
    public void mouseClicked(MouseEvent e) {
      try {
        Desktop.getDesktop().browse(new URI("https://github.com/syndersage/AsymCrypt"));
      } catch (URISyntaxException | IOException ignored) {
      }
    }

    @Override
    public void mousePressed(MouseEvent e) {

    }

    @Override
    public void mouseReleased(MouseEvent e) {

    }

    @Override
    public void mouseEntered(MouseEvent e) {
      githubLabel.setText("<html><a href=''>GitHub</a></html>");
    }

    @Override
    public void mouseExited(MouseEvent e) {
      githubLabel.setText("GitHub");
    }
  }

  public static void main(String[] args) {

    try {
      System.out.println(javax.swing.UIManager.getDefaults().getFont("Label.font"));
      UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
      UIManager.put("ToolTip.font", new Font("Dialog", Font.PLAIN, 10));
    } catch (Exception e) {
      System.out.println(e.getMessage());
    }
    SwingUtilities.invokeLater(MainForm::new);
  }
}
