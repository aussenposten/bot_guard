<?php

namespace Drupal\bot_guard\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * Form for decoding block tokens.
 */
class TokenDecoderForm extends FormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'bot_guard_token_decoder_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $form['token'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Token'),
      '#maxlength' => 500,
      '#size' => 64,
      '#attributes' => [
        'placeholder' => 'BG1a2b...',
        'style' => 'font-family: monospace;',
      ],
      '#default_value' => \Drupal::request()->query->get('token', ''),
    ];

    $form['actions'] = [
      '#type' => 'actions',
    ];

    $form['actions']['submit'] = [
      '#type' => 'submit',
      '#value' => $this->t('Decode Token'),
      '#button_type' => 'primary',
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $token = $form_state->getValue('token');
    
    // Redirect to dashboard with token as query parameter
    $form_state->setRedirect('bot_guard.dashboard', [], [
      'query' => ['token' => $token],
    ]);
  }

}
